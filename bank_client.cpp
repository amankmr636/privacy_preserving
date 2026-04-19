#include "federated_common.hpp"

using namespace ffkm;

int main(int argc, char** argv) {
  const std::string host = (argc > 1) ? argv[1] : "127.0.0.1";
  const std::size_t K = (argc > 2) ? std::stoul(argv[2]) : 3;
  const std::size_t maxIters = (argc > 3) ? std::stoul(argv[3]) : 2;

  auto artifacts = BuildContextAndKeys();
  auto data = Normalize01(LoadCsvNumeric("data/bank.csv"));
  AddDpNoise(data, 0.002);

  int sock = Connect(host, kPortBank);

  for (std::size_t iter = 0; iter < maxIters; ++iter) {
    auto encCentroids = recvCipherVector(sock);
    if (!encCentroids) throw std::runtime_error("receive centroids failed");

    auto partial = ComputePartialSquaredDistancesWithEncryptedCentroids(
        artifacts.cc, artifacts.jointPublicKey, data, *encCentroids, K, 3);
    sendCipherVector(sock, partial);

    auto indicators = recvCipherVector(sock);
    auto metrics = recvCipherVector(sock);
    auto fraudScores = recvCipherVector(sock);
    if (!indicators || !metrics || !fraudScores)
      throw std::runtime_error("receive iteration payload failed");

    auto centroidComponents = ComputeEncryptedCentroidComponents(
        artifacts.cc, artifacts.jointPublicKey, data, *indicators, 0.001,
        27 + iter);
    sendCipherVector(sock, centroidComponents);
  }

  auto finalIndicators = recvCipherVector(sock);
  auto finalMetrics = recvCipherVector(sock);
  auto finalFraudScores = recvCipherVector(sock);
  auto finalCentroids = recvCipherVector(sock);
  if (!finalIndicators || !finalMetrics || !finalFraudScores || !finalCentroids)
    throw std::runtime_error("receive final payload failed");

  close(sock);
  return 0;
}
