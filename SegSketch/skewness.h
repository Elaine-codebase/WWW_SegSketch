#pragma once
#include <vector>
#include <cstdint>
#include <cmath>
#include <numeric>

/// 偏斜度计算模式：Ratio（段内1的最大值/平均值）或 Entropy（段内概率熵）
enum class SkewMode {
    RATIO,
    ENTROPY
};

/// Ratio 方式：max_i(counts[i]) / mean(counts)
inline double computeSkewRatio(const std::vector<uint32_t>& counts) {
    if (counts.empty()) return 0.0;
    uint32_t max_n = 0;
    double sum = 0.0;
    for (auto n : counts) {
        max_n = std::max(max_n, n);
        sum += n;
    }
    double mean = sum / counts.size();
    return (mean > 0.0 ? static_cast<double>(max_n) / mean : 0.0);
}

/// Entropy 方式：-Σ p_i * ln(p_i)，p_i = counts[i] / N
inline double computeSkewEntropy(const std::vector<uint32_t>& counts) {
    double N = std::accumulate(counts.begin(), counts.end(), 0.0);
    if (N <= 0.0) return 0.0;
    double H = 0.0;
    for (auto n : counts) {
        if (n == 0) continue;
        double p = n / N;
        H -= p * std::log(p);
    }
    return H;
}

/// 通用接口
inline double computeSkewness(const std::vector<uint32_t>& counts, SkewMode mode) {
    return (mode == SkewMode::RATIO) ? computeSkewRatio(counts) : computeSkewEntropy(counts);
}
