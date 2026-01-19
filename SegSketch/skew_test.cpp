#include <iostream>
#include <vector>
#include "skewness.h"

using namespace std;

void runCase(const vector<uint32_t>& counts, const string& name) {
    double r = computeSkewRatio(counts);
    double e = computeSkewEntropy(counts);
    cout << name << " counts = [ ";
    for (auto v : counts) cout << v << " ";
    cout << "]\n";
    cout << "  Ratio skew   = " << r << "\n";
    cout << "  Entropy skew = " << e << "\n" << endl;
}

int main() {
    runCase({10,10,10,10}, "Uniform");
    runCase({40,0,0,0},    "One-hot");
    runCase({20,5,5,5},    "Slight-skew");
    runCase({30,5,3,2},    "Medium-skew");
    return 0;
}