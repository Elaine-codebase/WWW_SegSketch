
# SegSketch Super Host Detection

This project implements SegSketch, a memory-efficient sketch-based approach for detecting super hosts in a network. The system uses CAIDA datasets to identify spreaders and receivers within the context of super host detection.

## Datasets

- **caida33_Spreader.dat**: This file contains the dataset for super hosts that act as **spreaders**.
- **caida33_Receiver.dat**: This file contains the dataset for super hosts that act as **receivers**. In this dataset, we have reversed the src and dst positions, so that our SegSketch can directly apply to this dataset for detecting malicious super-receiver hosts.

## Compilation

To compile the project, use the following command in your terminal:

```bash
g++ -Wall -o main.out main.cpp hash.h loader.cpp loader.h skewness.h -lpcap
```

This command will generate an executable named `main.out`.

## Running SegSketch

To run the SegSketch system, execute the following command:

```bash
./main.out
```

This will launch the program and run SegSketch using the datasets for super host detection.
