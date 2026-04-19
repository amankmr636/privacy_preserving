#pragma once

#include <openfhe.h>

#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <fstream>
#include <limits>
#include <netinet/in.h>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace ffkm {

using namespace lbcrypto;

inline constexpr uint32_t kBatchSize = 4096;
inline constexpr uint32_t kScalingModSize = 60;
inline constexpr uint32_t kMultDepth = 24;
inline constexpr int kPortAggregator = 9000;
inline constexpr int kPortBank = 9001;
inline constexpr int kPortTelecom = 9002;

struct CryptoArtifacts {
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> jointPublicKey;
  PrivateKey<DCRTPoly> skAadhaar;
  PrivateKey<DCRTPoly> skBank;
  PrivateKey<DCRTPoly> skTelecom;
};

CryptoArtifacts BuildContextAndKeys();

std::vector<std::vector<double>> LoadCsvNumeric(const std::string& path,
                                                bool hasHeader = true);
std::vector<std::vector<double>> Normalize01(
    const std::vector<std::vector<double>>& matrix);
void AddDpNoise(std::vector<std::vector<double>>& matrix, double sigma = 0.0,
                uint64_t seed = 7);

std::vector<double> LoadCentroidFile(const std::string& path);
std::vector<std::vector<double>> LoadCentroids(const std::string& folder,
                                               std::size_t k);

Ciphertext<DCRTPoly> EncryptVector(CryptoContext<DCRTPoly> cc,
                                   PublicKey<DCRTPoly> pk,
                                   const std::vector<double>& values);
Ciphertext<DCRTPoly> EncryptConstantVector(CryptoContext<DCRTPoly> cc,
                                           PublicKey<DCRTPoly> pk,
                                           double value,
                                           std::size_t slots = kBatchSize);

bool SendAll(int sock, const void* data, std::size_t n);
bool RecvAll(int sock, void* data, std::size_t n);
bool sendBlob(int sock, const std::string& blob);
std::optional<std::string> recvBlob(int sock);

bool sendCiphertext(int sock, const Ciphertext<DCRTPoly>& ct);
std::optional<Ciphertext<DCRTPoly>> recvCiphertext(int sock);
bool sendCipherVector(int sock, const std::vector<Ciphertext<DCRTPoly>>& cts);
std::optional<std::vector<Ciphertext<DCRTPoly>>> recvCipherVector(int sock);

int Connect(const std::string& host, int port);
int ListenAndAccept(int port);

std::vector<double> Column(const std::vector<std::vector<double>>& matrix,
                           std::size_t col);

std::vector<Ciphertext<DCRTPoly>> EncryptCentroidSlice(
    CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk,
    const std::vector<std::vector<double>>& centroidSlice,
    std::size_t packedSlots);

std::vector<Ciphertext<DCRTPoly>> ComputePartialSquaredDistancesWithEncryptedCentroids(
    CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk,
    const std::vector<std::vector<double>>& localData,
    const std::vector<Ciphertext<DCRTPoly>>& encCentroidSlice, std::size_t k,
    std::size_t localFeatureCount);

std::vector<Ciphertext<DCRTPoly>> ApproxArgMinIndicators(
    CryptoContext<DCRTPoly> cc, const std::vector<Ciphertext<DCRTPoly>>& dTotal);

Ciphertext<DCRTPoly> SumSlots(CryptoContext<DCRTPoly> cc,
                              const Ciphertext<DCRTPoly>& ct);
Ciphertext<DCRTPoly> NewtonInverse(CryptoContext<DCRTPoly> cc,
                                   const Ciphertext<DCRTPoly>& x,
                                   std::size_t iters = 3,
                                   double init = 0.25);

std::vector<Ciphertext<DCRTPoly>> ComputeEncryptedCentroidComponents(
    CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk,
    const std::vector<std::vector<double>>& localData,
    const std::vector<Ciphertext<DCRTPoly>>& indicators,
    double dpSigma = 0.001, uint64_t seed = 7);

}  // namespace ffkm
