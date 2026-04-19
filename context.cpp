#include "federated_common.hpp"

namespace ffkm {

CryptoArtifacts BuildContextAndKeys() {
  CCParams<CryptoContextCKKSRNS> params;
  params.SetMultiplicativeDepth(kMultDepth);
  params.SetScalingModSize(kScalingModSize);
  params.SetBatchSize(kBatchSize);
  params.SetSecurityLevel(HEStd_128_classic);

  auto cc = GenCryptoContext(params);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);
  cc->Enable(MULTIPARTY);

  auto kpA = cc->KeyGen();
  auto kpB = cc->MultipartyKeyGen(kpA.publicKey);
  auto kpT = cc->MultipartyKeyGen(kpB.publicKey);

  cc->EvalMultKeyGen(kpA.secretKey);
  std::vector<int32_t> rot;
  for (int s = 1; s <= 4096; s <<= 1) {
    rot.push_back(s);
    rot.push_back(-s);
  }
  cc->EvalAtIndexKeyGen(kpA.secretKey, rot);
  cc->EvalSumKeyGen(kpA.secretKey);

  return CryptoArtifacts{cc, kpT.publicKey, kpA.secretKey, kpB.secretKey,
                         kpT.secretKey};
}

std::vector<std::vector<double>> LoadCsvNumeric(const std::string& path,
                                                bool hasHeader) {
  std::ifstream in(path);
  if (!in) throw std::runtime_error("Cannot open csv: " + path);

  std::vector<std::vector<double>> out;
  std::string line;
  if (hasHeader) std::getline(in, line);
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    std::stringstream ss(line);
    std::string tok;
    std::vector<double> row;
    while (std::getline(ss, tok, ',')) row.push_back(std::stod(tok));
    out.push_back(std::move(row));
  }
  return out;
}

std::vector<std::vector<double>> Normalize01(
    const std::vector<std::vector<double>>& matrix) {
  if (matrix.empty()) return {};
  const std::size_t d = matrix[0].size();

  std::vector<double> mn(d, std::numeric_limits<double>::max());
  std::vector<double> mx(d, std::numeric_limits<double>::lowest());
  for (const auto& row : matrix) {
    for (std::size_t j = 0; j < d; ++j) {
      mn[j] = std::min(mn[j], row[j]);
      mx[j] = std::max(mx[j], row[j]);
    }
  }

  std::vector<std::vector<double>> out = matrix;
  for (auto& row : out) {
    for (std::size_t j = 0; j < d; ++j) {
      const double den = std::max(1e-12, mx[j] - mn[j]);
      row[j] = (row[j] - mn[j]) / den;
    }
  }
  return out;
}

void AddDpNoise(std::vector<std::vector<double>>& matrix, double sigma,
                uint64_t seed) {
  if (sigma <= 0.0) return;
  std::mt19937_64 gen(seed);
  std::normal_distribution<double> gauss(0.0, sigma);
  for (auto& row : matrix) {
    for (double& v : row) v = std::clamp(v + gauss(gen), 0.0, 1.0);
  }
}

std::vector<double> LoadCentroidFile(const std::string& path) {
  std::ifstream in(path);
  if (!in) throw std::runtime_error("Cannot open centroid file: " + path);
  std::vector<double> values;
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty()) values.push_back(std::stod(line));
  }
  return values;
}

std::vector<std::vector<double>> LoadCentroids(const std::string& folder,
                                               std::size_t k) {
  std::vector<std::vector<double>> c;
  c.reserve(k);
  for (std::size_t i = 1; i <= k; ++i) {
    c.push_back(LoadCentroidFile(folder + "/centroid" + std::to_string(i) + ".txt"));
  }
  return c;
}

Ciphertext<DCRTPoly> EncryptVector(CryptoContext<DCRTPoly> cc,
                                   PublicKey<DCRTPoly> pk,
                                   const std::vector<double>& values) {
  return cc->Encrypt(pk, cc->MakeCKKSPackedPlaintext(values));
}

Ciphertext<DCRTPoly> EncryptConstantVector(CryptoContext<DCRTPoly> cc,
                                           PublicKey<DCRTPoly> pk, double value,
                                           std::size_t slots) {
  return EncryptVector(cc, pk, std::vector<double>(slots, value));
}

bool SendAll(int sock, const void* data, std::size_t n) {
  const uint8_t* p = static_cast<const uint8_t*>(data);
  std::size_t done = 0;
  while (done < n) {
    const ssize_t s = send(sock, p + done, n - done, 0);
    if (s <= 0) return false;
    done += static_cast<std::size_t>(s);
  }
  return true;
}

bool RecvAll(int sock, void* data, std::size_t n) {
  uint8_t* p = static_cast<uint8_t*>(data);
  std::size_t done = 0;
  while (done < n) {
    const ssize_t r = recv(sock, p + done, n - done, 0);
    if (r <= 0) return false;
    done += static_cast<std::size_t>(r);
  }
  return true;
}

bool sendBlob(int sock, const std::string& blob) {
  uint64_t len = htobe64(static_cast<uint64_t>(blob.size()));
  return SendAll(sock, &len, sizeof(len)) && SendAll(sock, blob.data(), blob.size());
}

std::optional<std::string> recvBlob(int sock) {
  uint64_t beLen = 0;
  if (!RecvAll(sock, &beLen, sizeof(beLen))) return std::nullopt;
  uint64_t len = be64toh(beLen);
  std::string out(len, '\0');
  if (!RecvAll(sock, out.data(), len)) return std::nullopt;
  return out;
}

bool sendCiphertext(int sock, const Ciphertext<DCRTPoly>& ct) {
  std::stringstream ss;
  Serial::Serialize(ct, ss, SerType::BINARY);
  return sendBlob(sock, ss.str());
}

std::optional<Ciphertext<DCRTPoly>> recvCiphertext(int sock) {
  auto blob = recvBlob(sock);
  if (!blob) return std::nullopt;
  Ciphertext<DCRTPoly> ct;
  std::stringstream ss(*blob);
  Serial::Deserialize(ct, ss, SerType::BINARY);
  return ct;
}

bool sendCipherVector(int sock, const std::vector<Ciphertext<DCRTPoly>>& cts) {
  uint64_t beCount = htobe64(static_cast<uint64_t>(cts.size()));
  if (!SendAll(sock, &beCount, sizeof(beCount))) return false;
  for (const auto& ct : cts) {
    if (!sendCiphertext(sock, ct)) return false;
  }
  return true;
}

std::optional<std::vector<Ciphertext<DCRTPoly>>> recvCipherVector(int sock) {
  uint64_t beCount = 0;
  if (!RecvAll(sock, &beCount, sizeof(beCount))) return std::nullopt;
  const uint64_t count = be64toh(beCount);
  std::vector<Ciphertext<DCRTPoly>> out;
  out.reserve(static_cast<std::size_t>(count));
  for (uint64_t i = 0; i < count; ++i) {
    auto ct = recvCiphertext(sock);
    if (!ct) return std::nullopt;
    out.push_back(*ct);
  }
  return out;
}

int Connect(const std::string& host, int port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) throw std::runtime_error("socket failed");
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
  if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(s);
    throw std::runtime_error("connect failed");
  }
  return s;
}

int ListenAndAccept(int port) {
  int ls = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) throw std::runtime_error("socket failed");
  int one = 1;
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);
  if (bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    throw std::runtime_error("bind failed");
  if (listen(ls, 8) != 0) throw std::runtime_error("listen failed");
  int cs = accept(ls, nullptr, nullptr);
  close(ls);
  return cs;
}

std::vector<double> Column(const std::vector<std::vector<double>>& matrix,
                           std::size_t col) {
  std::vector<double> out(matrix.size());
  for (std::size_t i = 0; i < matrix.size(); ++i) out[i] = matrix[i][col];
  return out;
}

std::vector<Ciphertext<DCRTPoly>> EncryptCentroidSlice(
    CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk,
    const std::vector<std::vector<double>>& centroidSlice,
    std::size_t packedSlots) {
  std::vector<Ciphertext<DCRTPoly>> out;
  for (const auto& c : centroidSlice) {
    for (double value : c) {
      out.push_back(EncryptConstantVector(cc, pk, value, packedSlots));
    }
  }
  return out;
}

std::vector<Ciphertext<DCRTPoly>> ComputePartialSquaredDistancesWithEncryptedCentroids(
    CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk,
    const std::vector<std::vector<double>>& localData,
    const std::vector<Ciphertext<DCRTPoly>>& encCentroidSlice, std::size_t k,
    std::size_t localFeatureCount) {
  std::vector<Ciphertext<DCRTPoly>> partial;
  partial.reserve(k);

  for (std::size_t cluster = 0; cluster < k; ++cluster) {
    Ciphertext<DCRTPoly> accum;
    bool first = true;
    for (std::size_t f = 0; f < localFeatureCount; ++f) {
      auto x = EncryptVector(cc, pk, Column(localData, f));
      auto mu = encCentroidSlice[cluster * localFeatureCount + f];
      auto diff = cc->EvalSub(x, mu);
      auto sq = cc->EvalMult(diff, diff);
      accum = first ? sq : cc->EvalAdd(accum, sq);
      first = false;
    }
    partial.push_back(accum);
  }
  return partial;
}

std::vector<Ciphertext<DCRTPoly>> ApproxArgMinIndicators(
    CryptoContext<DCRTPoly> cc, const std::vector<Ciphertext<DCRTPoly>>& dTotal) {
  std::vector<Ciphertext<DCRTPoly>> indicators;
  indicators.reserve(dTotal.size());
  for (std::size_t k = 0; k < dTotal.size(); ++k) {
    Ciphertext<DCRTPoly> prod;
    bool first = true;
    for (std::size_t j = 0; j < dTotal.size(); ++j) {
      if (k == j) continue;
      auto delta = cc->EvalSub(dTotal[j], dTotal[k]);
      auto step = cc->EvalAdd(cc->EvalMult(delta, -0.25), 0.5);
      prod = first ? step : cc->EvalMult(prod, step);
      first = false;
    }
    indicators.push_back(prod);
  }
  return indicators;
}

Ciphertext<DCRTPoly> SumSlots(CryptoContext<DCRTPoly> cc,
                              const Ciphertext<DCRTPoly>& ct) {
  return cc->EvalSum(ct, kBatchSize);
}

Ciphertext<DCRTPoly> NewtonInverse(CryptoContext<DCRTPoly> cc,
                                   const Ciphertext<DCRTPoly>& x,
                                   std::size_t iters, double init) {
  Ciphertext<DCRTPoly> y = cc->EvalAdd(cc->EvalMult(x, 0.0), init);
  for (std::size_t i = 0; i < iters; ++i) {
    auto xy = cc->EvalMult(x, y);
    auto term = cc->EvalSub(2.0, xy);
    y = cc->EvalMult(y, term);
  }
  return y;
}

std::vector<Ciphertext<DCRTPoly>> ComputeEncryptedCentroidComponents(
    CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk,
    const std::vector<std::vector<double>>& localData,
    const std::vector<Ciphertext<DCRTPoly>>& indicators, double dpSigma,
    uint64_t seed) {
  const std::size_t K = indicators.size();
  const std::size_t d = localData.empty() ? 0 : localData[0].size();

  std::mt19937_64 gen(seed);
  std::normal_distribution<double> gauss(0.0, dpSigma);

  std::vector<Ciphertext<DCRTPoly>> components;
  components.reserve(K * d);
  for (std::size_t k = 0; k < K; ++k) {
    auto clusterSize = SumSlots(cc, indicators[k]);
    auto invSize = NewtonInverse(cc, clusterSize);
    for (std::size_t j = 0; j < d; ++j) {
      auto featureEnc = EncryptVector(cc, pk, Column(localData, j));
      auto weighted = cc->EvalMult(featureEnc, indicators[k]);
      auto numerator = SumSlots(cc, weighted);
      auto centroid = cc->EvalMult(numerator, invSize);
      centroid = cc->EvalAdd(centroid, gauss(gen));
      components.push_back(centroid);
    }
  }
  return components;
}

}  // namespace ffkm
