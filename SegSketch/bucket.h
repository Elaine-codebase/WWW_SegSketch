#include <vector>
#include <cmath>
#include <algorithm>

using namespace std;

const int TREE_DEPTH = 8;
const int BUCKET_NUM = 1024; // 可自定义桶数

struct TreeNode {
    bool is_root;
    int count;        // 仅根节点使用
    bool visited;     // 其他节点使用
    TreeNode* left;
    TreeNode* right;

    TreeNode(bool root = false) {
        is_root = root;
        if (is_root) {
            count = 0;
        } else {
            visited = false;
        }
        left = nullptr;
        right = nullptr;
    }
};

// 递归生成满二叉树
TreeNode* buildTree(int current_depth, int max_depth, bool is_root = false) {
    if (current_depth > max_depth) return nullptr;

    TreeNode* node = new TreeNode(is_root);
    node->left = buildTree(current_depth + 1, max_depth);
    node->right = buildTree(current_depth + 1, max_depth);
    return node;
}


std::vector<bool> bitmap_union(std::vector<bool>& bitmap, const std::vector<bool>& oldbitmap) {
    std::vector<bool> uinbit(bitmap.size(),false);
    for (size_t i = 0; i < bitmap.size(); ++i) {
        uinbit[i] = bitmap[i] || oldbitmap[i];
    }
    return uinbit;
}
// 桶的数据结构
class Bucket 
{
public:
    struct bucket
    {
        uint32_t sourceIP;          // 源ip
        std::vector<bool> bitmap;   // 大小可变的位图
        std::vector<bool> oldbitmap;
        double count=0;               // 倾斜度
        double hit=0;
        double left=0;
        double right=0;
        // 默认构造函数
        bucket() : sourceIP(0), count(0.0) {}

        // 构造函数
        bucket(uint32_t ip, size_t bitmapSize, int argCount): sourceIP(ip), bitmap(bitmapSize, false),oldbitmap(128,false), count(argCount) {}

        // 比较函数
        bool operator==(const bucket& other) const {
            return sourceIP == other.sourceIP && count == other.count;
        }
    };
    
    // 比较函数
    struct CompareBucket {
        bool operator()(const bucket& a, const bucket& b) {
            return a.count < b.count; // 大根堆：count较大的元素优先级更高
        }
    };
    
    // 计算倾斜度（1）：E[(X-mean)^3] / stdDev^3
    // 计算倾斜度（2）：b * ln(b/z)
    static double CalculateSkewness(std::vector<bool> argBitmap) {
        double mean = 0.0;
        double variance = 0.0;
        double skewness = 0.0;
        int size = argBitmap.size();
        // 1.计算均值
        //std::cout<<"size"<<size<<std::endl;
        //for(bool it:argBitmap)
        //if(it)
          //      std::cout<<"cc"<<it<<std::endl;
        mean = double(std::count(argBitmap.begin(), argBitmap.end(), true)) / double(size);
      //  std::cout << std::count(argBitmap.begin(), argBitmap.end(), true) << ", mean: " << mean << "\n";
        // 2.计算方差
        for (bool bit : argBitmap) {
            variance += std::pow(bit - mean, 2);
        }
        variance /= size;
        // 3.计算标准差
        double stdDev = std::sqrt(variance);
        if (stdDev == 0)  return 0.0;
        // 4.计算倾斜度
        for (bool bit : argBitmap) {
            skewness += std::pow(bit - mean, 3);
        }
        skewness /= size;
        skewness /= std::pow(stdDev, 3);

       // std::cout << "count: " << std::count(argBitmap.begin(), argBitmap.end(), true) << ", mean: " << mean << ", stdDev: " << stdDev;
        //std::cout << ", skewness: " << skewness << "\n";
        return skewness;

        // int b = argBitmap.size();
        // int z = std::count(argBitmap.begin(), argBitmap.end(), 1);
        // double skewness = b * std::log(static_cast<double>(b) / z);
        // return skewness;
    }

#include <vector>
#include <iostream>


static double sxsSkewness(std::vector<bool> argBitmap) {
        double mean = 0.0;
        double variance = 0.0;
        double skewness = 0.0;
        double max=0;
        for(int i=1;i<=1024/4;i++){
        int shifted_bits = 1024-i*4;
                
        int size = argBitmap.size();
        // 1.计算均值
        variance = std::count(argBitmap.begin()+shifted_bits, argBitmap.end()-(i-1)*4, true);
        //std::cout<<"ui"<<i<<" "<<variance<<std::endl;
        mean+=variance;
        
        if(max<variance)
            max=variance;
        // std::cout << std::count(argBitmap.begin(), argBitmap.end(), true) << ", mean: " << mean << "\n";
        // 2.计算方差
        }
        mean/=double(1024/4);

        // std::cout << "count: " << std::count(argBitmap.begin(), argBitmap.end(), true) << ", mean: " << mean << ", stdDev: " << stdDev;
        // std::cout << ", skewness: " << skewness << "\n";
        return double(max)/double(mean);

        // int b = argBitmap.size();
        // int z = std::count(argBitmap.begin(), argBitmap.end(), 1);
        // double skewness = b * std::log(static_cast<double>(b) / z);
        // return skewness;
    }
    // 计算bitmap中的所有段的1的个数的最大值 / 非零段数
    static double CalculateIndicator(std::vector<bool> argBitmap, int segments, int segmentSize) {
        int max = -1;
        int nonZeroSegments = 0;
        double mean=0;
        //std::cout<<"segment"<<segmentSize<<std::endl;
        for (int i = 0; i < segments; ++i) {
            int trueCounts = std::count(argBitmap.begin() + i * segmentSize, argBitmap.begin() + (i + 1) * segmentSize, true);
            // std::cout << trueCounts << " ";
            mean+=std::count(argBitmap.begin() + i * segmentSize, argBitmap.begin() + (i + 1) * segmentSize, true);
            
            max = max > trueCounts ? max : trueCounts;
            nonZeroSegments = trueCounts > 0 ? nonZeroSegments + 1 : nonZeroSegments;
        }
       // std::cout<<nonZeroSegments<<std::endl;
        // std::cout << "\n";
        return max / nonZeroSegments;
    }

    // 维护大根堆
    static void maintainHeap(std::priority_queue<bucket, std::vector<bucket>, CompareBucket>& heap, bucket newBucket, int k) {
        // 遍历堆，查找是否存在相同sourceIP的bucket
        std::priority_queue<bucket, std::vector<bucket>, CompareBucket> tempHeap = heap;
        bool found = false;
        while (!tempHeap.empty()) {
            if (tempHeap.top().sourceIP == newBucket.sourceIP) {
                found = true;
                break;
            }
            tempHeap.pop();
        }

        if (found) {
            // 如果找到相同sourceIP的bucket，检查是否需要更新count
            std::vector<bucket> tempVector;
            while (!heap.empty()) {
                bucket current = heap.top();
                heap.pop();
                if (current.sourceIP == newBucket.sourceIP) {
                    // 如果找到相同sourceIP的bucket，更新count
                    if (newBucket.count > current.count) {
                        current.count = newBucket.count;
                    }
                }
                tempVector.push_back(current);
            }

            // 将更新后的元素重新插入堆中
            for (const auto& b : tempVector) {
                heap.push(b);
            }
        } else {
            // 如果堆中不存在相同sourceIP的bucket
            if (int(heap.size()) < k) {
                // 如果当前大小小于k，直接插入
                heap.push(newBucket);
            } else {
                // 如果当前大小等于k，检查是否替换
                bucket topBucket = heap.top();
                if (CompareBucket()(newBucket, topBucket)) {
                    // 如果新元素比堆顶元素更优先，替换堆顶元素
                    heap.pop();
                    heap.push(newBucket);
                }
            }
        }
    }
};
