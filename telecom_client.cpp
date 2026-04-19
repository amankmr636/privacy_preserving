#include "federated_common.hpp"

using namespace ffkm;

namespace {

std::vector<double> DecryptSlots(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk,
                                 const Ciphertext<DCRTPoly>& ct,
                                 std::size_t length) {
  Plaintext pt;
  cc->Decrypt(sk, ct, &pt);
  pt->SetLength(length);
  auto vals = pt->GetRealPackedValue();
  if (vals.size() > length) vals.resize(length);
  return vals;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string host = (argc > 1) ? argv[1] : "127.0.0.1";
  const std::size_t K = (argc > 2) ? std::stoul(argv[2]) : 3;
  const std::size_t maxIters = (argc > 3) ? std::stoul(argv[3]) : 2;

  auto artifacts = BuildContextAndKeys();
  auto data = Normalize01(LoadCsvNumeric("data/telecom.csv"));
  AddDpNoise(data, 0.002);

  int sock = Connect(host, kPortTelecom);

  for (std::size_t iter = 0; iter < maxIters; ++iter) {
    auto encCentroids = recvCipherVector(sock);
    if (!encCentroids) throw std::runtime_error("receive centroids failed");

    auto partial = ComputePartialSquaredDistancesWithEncryptedCentroids(
        artifacts.cc, artifacts.jointPublicKey, data, *encCentroids, K, 4);
    sendCipherVector(sock, partial);

    auto indicators = recvCipherVector(sock);
    auto metrics = recvCipherVector(sock);
    auto fraudScores = recvCipherVector(sock);
    if (!indicators || !metrics || !fraudScores)
      throw std::runtime_error("receive iteration payload failed");

    auto centroidComponents = ComputeEncryptedCentroidComponents(
        artifacts.cc, artifacts.jointPublicKey, data, *indicators, 0.001,
        37 + iter);
    sendCipherVector(sock, centroidComponents);
  }

  auto finalIndicators = recvCipherVector(sock);
  auto finalMetrics = recvCipherVector(sock);
  auto finalFraudScores = recvCipherVector(sock);
  auto finalCentroids = recvCipherVector(sock);
  if (!finalIndicators || !finalMetrics || !finalFraudScores || !finalCentroids)
    throw std::runtime_error("receive final payload failed");

  const std::size_t nUsers = data.size();

  std::vector<std::vector<double>> indSlots(K);
  for (std::size_t k = 0; k < K; ++k) {
    indSlots[k] = DecryptSlots(artifacts.cc, artifacts.skTelecom,
                               (*finalIndicators)[k], nUsers);
  }
  std::ofstream assignmentOut("cluster_assignments.csv");
  assignmentOut << "user_index,cluster\n";
  for (std::size_t i = 0; i < nUsers; ++i) {
    std::size_t best = 0;
    for (std::size_t k = 1; k < K; ++k) {
      if (indSlots[k][i] > indSlots[best][i]) best = k;
    }
    assignmentOut << i << ',' << best << "\n";
  }

  auto fraudScores = DecryptSlots(artifacts.cc, artifacts.skTelecom,
                                  (*finalFraudScores)[0], nUsers);
  std::ofstream fraudScoreOut("fraud_scores.csv");
  fraudScoreOut << "user_index,fraud_score\n";
  for (std::size_t i = 0; i < nUsers; ++i) {
    fraudScoreOut << i << ',' << fraudScores[i] << "\n";
  }

  std::vector<std::pair<double, std::size_t>> order;
  order.reserve(nUsers);
  for (std::size_t i = 0; i < nUsers; ++i) order.push_back({fraudScores[i], i});
  std::sort(order.begin(), order.end(),
            [](const auto& a, const auto& b) { return a.first > b.first; });

  std::ofstream fraudRankOut("fraud_rankings.csv");
  fraudRankOut << "rank,user_index,fraud_score\n";
  for (std::size_t r = 0; r < order.size(); ++r) {
    fraudRankOut << (r + 1) << ',' << order[r].second << ',' << order[r].first
                 << "\n";
  }

  auto wcss =
      DecryptSlots(artifacts.cc, artifacts.skTelecom, (*finalMetrics)[0], 1)[0];
  auto silhouette =
      DecryptSlots(artifacts.cc, artifacts.skTelecom, (*finalMetrics)[1], 1)[0];
  std::ofstream metricsOut("metrics.csv");
  metricsOut << "metric,value\n";
  metricsOut << "wcss," << wcss << "\n";
  metricsOut << "silhouette," << silhouette << "\n";

  std::ofstream centroidOut("cluster_centroids.csv");
  centroidOut << "cluster,feature_index,value\n";
  for (std::size_t idx = 0; idx < (*finalCentroids).size(); ++idx) {
    auto value = DecryptSlots(artifacts.cc, artifacts.skTelecom,
                              (*finalCentroids)[idx], 1)[0];
    centroidOut << (idx / 10) << ',' << (idx % 10) << ',' << value << "\n";
  }

  close(sock);
  return 0;
}
