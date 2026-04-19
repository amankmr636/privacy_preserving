#include "federated_common.hpp"

using namespace ffkm;

namespace {

std::vector<std::vector<double>> Slice(const std::vector<std::vector<double>>& full,
                                       std::size_t begin, std::size_t end) {
  std::vector<std::vector<double>> out;
  out.reserve(full.size());
  for (const auto& c : full) {
    out.push_back(std::vector<double>(c.begin() + static_cast<long>(begin),
                                      c.begin() + static_cast<long>(end)));
  }
  return out;
}

void SendEncryptedCentroidSlice(int sock, CryptoContext<DCRTPoly> cc,
                                PublicKey<DCRTPoly> pk,
                                const std::vector<std::vector<double>>& slice,
                                std::size_t slotCount) {
  auto enc = EncryptCentroidSlice(cc, pk, slice, slotCount);
  sendCipherVector(sock, enc);
}

std::vector<Ciphertext<DCRTPoly>> FlattenFullCentroidsFromComponents(
    std::size_t k, const std::vector<Ciphertext<DCRTPoly>>& aadhaar,
    const std::vector<Ciphertext<DCRTPoly>>& bank,
    const std::vector<Ciphertext<DCRTPoly>>& telecom) {
  std::vector<Ciphertext<DCRTPoly>> full;
  full.reserve(k * 10);
  for (std::size_t i = 0; i < k; ++i) {
    for (std::size_t f = 0; f < 3; ++f) full.push_back(aadhaar[i * 3 + f]);
    for (std::size_t f = 0; f < 3; ++f) full.push_back(bank[i * 3 + f]);
    for (std::size_t f = 0; f < 4; ++f) full.push_back(telecom[i * 4 + f]);
  }
  return full;
}

Ciphertext<DCRTPoly> ApproxStep(CryptoContext<DCRTPoly> cc,
                                const Ciphertext<DCRTPoly>& x) {
  return cc->EvalAdd(cc->EvalMult(x, -0.25), 0.5);
}

}  // namespace

int main(int argc, char** argv) {
  const std::size_t K = (argc > 1) ? std::stoul(argv[1]) : 3;
  const std::size_t maxIters = (argc > 2) ? std::stoul(argv[2]) : 2;

  auto artifacts = BuildContextAndKeys();
  auto centroids = LoadCentroids("centroids", K);

  int aadhaarSock = ListenAndAccept(kPortAggregator);
  int bankSock = ListenAndAccept(kPortBank);
  int telecomSock = ListenAndAccept(kPortTelecom);

  std::vector<Ciphertext<DCRTPoly>> indicators;
  std::vector<Ciphertext<DCRTPoly>> dTotal;
  std::vector<Ciphertext<DCRTPoly>> metricsPayload;
  std::vector<Ciphertext<DCRTPoly>> fraudPayload;
  std::vector<Ciphertext<DCRTPoly>> encFullCentroids;

  for (std::size_t iter = 0; iter < maxIters; ++iter) {
    if (iter == 0) {
      SendEncryptedCentroidSlice(aadhaarSock, artifacts.cc, artifacts.jointPublicKey,
                                 Slice(centroids, 0, 3), kBatchSize);
      SendEncryptedCentroidSlice(bankSock, artifacts.cc, artifacts.jointPublicKey,
                                 Slice(centroids, 3, 6), kBatchSize);
      SendEncryptedCentroidSlice(telecomSock, artifacts.cc, artifacts.jointPublicKey,
                                 Slice(centroids, 6, 10), kBatchSize);
    } else {
      std::vector<Ciphertext<DCRTPoly>> aSlice;
      std::vector<Ciphertext<DCRTPoly>> bSlice;
      std::vector<Ciphertext<DCRTPoly>> tSlice;
      aSlice.reserve(K * 3);
      bSlice.reserve(K * 3);
      tSlice.reserve(K * 4);
      for (std::size_t i = 0; i < K; ++i) {
        const std::size_t base = i * 10;
        aSlice.insert(aSlice.end(), encFullCentroids.begin() + static_cast<long>(base),
                      encFullCentroids.begin() + static_cast<long>(base + 3));
        bSlice.insert(bSlice.end(), encFullCentroids.begin() + static_cast<long>(base + 3),
                      encFullCentroids.begin() + static_cast<long>(base + 6));
        tSlice.insert(tSlice.end(), encFullCentroids.begin() + static_cast<long>(base + 6),
                      encFullCentroids.begin() + static_cast<long>(base + 10));
      }
      sendCipherVector(aadhaarSock, aSlice);
      sendCipherVector(bankSock, bSlice);
      sendCipherVector(telecomSock, tSlice);
    }

    auto dA = recvCipherVector(aadhaarSock);
    auto dB = recvCipherVector(bankSock);
    auto dT = recvCipherVector(telecomSock);
    if (!dA || !dB || !dT) throw std::runtime_error("receive distances failed");

    dTotal.clear();
    for (std::size_t k = 0; k < K; ++k) {
      dTotal.push_back(
          artifacts.cc->EvalAdd(artifacts.cc->EvalAdd((*dA)[k], (*dB)[k]), (*dT)[k]));
    }

    indicators = ApproxArgMinIndicators(artifacts.cc, dTotal);

    // WCSS = sum distance^2.
    Ciphertext<DCRTPoly> wcss = SumSlots(artifacts.cc, artifacts.cc->EvalMult(dTotal[0], dTotal[0]));
    for (std::size_t k = 1; k < K; ++k) {
      wcss = artifacts.cc->EvalAdd(
          wcss,
          SumSlots(artifacts.cc, artifacts.cc->EvalMult(dTotal[k], dTotal[k])));
    }

    // Silhouette approximation: a=assigned distance, b=avg distance to other clusters,
    // s=(b-a)/(b+eps).
    Ciphertext<DCRTPoly> assigned = artifacts.cc->EvalMult(dTotal[0], indicators[0]);
    Ciphertext<DCRTPoly> totalDist = dTotal[0];
    for (std::size_t k = 1; k < K; ++k) {
      assigned = artifacts.cc->EvalAdd(assigned,
                                       artifacts.cc->EvalMult(dTotal[k], indicators[k]));
      totalDist = artifacts.cc->EvalAdd(totalDist, dTotal[k]);
    }
    auto otherAvg = artifacts.cc->EvalMult(artifacts.cc->EvalSub(totalDist, assigned),
                                           1.0 / static_cast<double>(K - 1));
    auto invB = NewtonInverse(artifacts.cc, artifacts.cc->EvalAdd(otherAvg, 1e-3), 3,
                              0.5);
    auto silhouette = artifacts.cc->EvalMult(artifacts.cc->EvalSub(otherAvg, assigned),
                                             invB);

    // Fraud cluster: cluster with largest average distance.
    std::vector<Ciphertext<DCRTPoly>> avgDist(K);
    for (std::size_t k = 0; k < K; ++k) {
      auto pop = SumSlots(artifacts.cc, indicators[k]);
      auto invPop = NewtonInverse(artifacts.cc, artifacts.cc->EvalAdd(pop, 1e-3));
      auto weighted = SumSlots(artifacts.cc,
                               artifacts.cc->EvalMult(indicators[k], dTotal[k]));
      avgDist[k] = artifacts.cc->EvalMult(weighted, invPop);
    }

    std::vector<Ciphertext<DCRTPoly>> fraudClusterWeight(K);
    for (std::size_t k = 0; k < K; ++k) {
      Ciphertext<DCRTPoly> w;
      bool first = true;
      for (std::size_t j = 0; j < K; ++j) {
        if (j == k) continue;
        auto step = ApproxStep(artifacts.cc, artifacts.cc->EvalSub(avgDist[j], avgDist[k]));
        w = first ? step : artifacts.cc->EvalMult(w, step);
        first = false;
      }
      fraudClusterWeight[k] = w;
    }

    Ciphertext<DCRTPoly> fraudScore = artifacts.cc->EvalMult(indicators[0], fraudClusterWeight[0]);
    for (std::size_t k = 1; k < K; ++k) {
      fraudScore = artifacts.cc->EvalAdd(
          fraudScore,
          artifacts.cc->EvalMult(indicators[k], fraudClusterWeight[k]));
    }

    metricsPayload = {wcss, silhouette};
    fraudPayload = {fraudScore};

    sendCipherVector(aadhaarSock, indicators);
    sendCipherVector(bankSock, indicators);
    sendCipherVector(telecomSock, indicators);
    sendCipherVector(aadhaarSock, metricsPayload);
    sendCipherVector(bankSock, metricsPayload);
    sendCipherVector(telecomSock, metricsPayload);
    sendCipherVector(aadhaarSock, fraudPayload);
    sendCipherVector(bankSock, fraudPayload);
    sendCipherVector(telecomSock, fraudPayload);

    auto cA = recvCipherVector(aadhaarSock);
    auto cB = recvCipherVector(bankSock);
    auto cT = recvCipherVector(telecomSock);
    if (!cA || !cB || !cT)
      throw std::runtime_error("receive centroid components failed");
    encFullCentroids = FlattenFullCentroidsFromComponents(K, *cA, *cB, *cT);
  }

  // Final encrypted payloads returned only to clients for decryption/export.
  if (!sendCipherVector(aadhaarSock, indicators) ||
      !sendCipherVector(bankSock, indicators) ||
      !sendCipherVector(telecomSock, indicators)) {
    throw std::runtime_error("send indicators failed");
  }
  if (!sendCipherVector(aadhaarSock, metricsPayload) ||
      !sendCipherVector(bankSock, metricsPayload) ||
      !sendCipherVector(telecomSock, metricsPayload)) {
    throw std::runtime_error("send metrics failed");
  }
  if (!sendCipherVector(aadhaarSock, fraudPayload) ||
      !sendCipherVector(bankSock, fraudPayload) ||
      !sendCipherVector(telecomSock, fraudPayload)) {
    throw std::runtime_error("send fraud scores failed");
  }
  if (!sendCipherVector(aadhaarSock, encFullCentroids) ||
      !sendCipherVector(bankSock, encFullCentroids) ||
      !sendCipherVector(telecomSock, encFullCentroids)) {
    throw std::runtime_error("send centroids failed");
  }

  close(aadhaarSock);
  close(bankSock);
  close(telecomSock);
  return 0;
}
