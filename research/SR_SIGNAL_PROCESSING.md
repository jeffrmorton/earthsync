# Schumann Resonance Signal Processing: Spectral Estimation and Peak Extraction

## Abstract

Schumann Resonance (SR) analysis requires extracting weak, quasi-stationary spectral peaks embedded in broadband noise. This document reviews the signal processing methods used across operational SR observatories and research groups, from classical spectral estimation through parametric fitting to modern machine learning approaches. We cover Welch periodograms, multitaper methods, Lorentzian curve fitting, peak detection algorithms, Q-burst identification, complexity metrics, and emerging deep learning techniques.

---

## 1. Spectral Estimation Methods

### 1.1 Welch Periodogram (Observatory Standard)

The Welch method of overlapped, windowed, averaged periodograms is the de facto standard for SR spectral estimation. It is used at the Sierra Nevada observatory (Gazquez Parra et al. 2015), the HeartMath GCMS network (McCraty et al. 2017), and the Chinese 12-station network (Zhou et al. 2023).

**Standard parameters:**

| Parameter        | Typical Value        | Rationale                                     |
|------------------|----------------------|-----------------------------------------------|
| Window function  | Hann (Hanning)       | Good spectral leakage suppression             |
| Segment length   | 10 seconds           | ~0.1 Hz frequency resolution                  |
| Overlap          | 50%                  | Standard for Hann window (optimal)            |
| Analysis window  | 10 minutes           | Balances stationarity vs. averaging           |
| Frequency range  | 3--45 Hz             | Covers modes 1--6                             |

A 10-minute analysis window with 10-second segments at 50% overlap yields approximately 119 averaged periodograms, reducing PSD variance by a factor of ~119 relative to a single periodogram. This level of averaging is sufficient to resolve the SR peaks above the noise floor under normal conditions.

**Frequency resolution considerations:**
The frequency resolution of Welch's method is determined by the segment length, not the total analysis window. With 10-second segments:

    delta_f = 1 / T_segment = 1 / 10 = 0.1 Hz

This resolution is adequate for tracking SR mode frequencies (which shift by 0.1--0.3 Hz on diurnal timescales) but may be insufficient for resolving fine structure. Longer segments improve resolution at the cost of fewer averages and potential non-stationarity.

### 1.2 Multitaper Spectral Estimation

Multitaper methods using Discrete Prolate Spheroidal Sequences (DPSS), also known as Slepian tapers, offer reduced variance from the same data length compared to Welch's method (Thomson 1982). The approach applies multiple orthogonal tapers to the same data segment, producing independent spectral estimates that are then averaged.

**Advantages for SR analysis:**

1. **Reduced variance**: For a time-bandwidth product NW = 4, the multitaper estimate uses K = 2*NW - 1 = 7 independent tapers, reducing variance by a factor of 7 versus a single taper
2. **No overlap needed**: All tapers are applied to the same data segment, avoiding the statistical dependence introduced by overlapping in Welch's method
3. **Bias control**: The spectral concentration of DPSS tapers within the resolution bandwidth is maximal by construction

**Typical parameters for SR:**

| Parameter             | Value     |
|-----------------------|-----------|
| Time-bandwidth (NW)   | 3--4      |
| Number of tapers (K)  | 5--7      |
| Segment length         | 10--60 s  |

Multitaper methods are particularly useful when short data segments are required (e.g., tracking rapid SR variations during geophysical events) and fewer averages are available.

### 1.3 Windowing Functions

While the Hann window is standard, other windows have been applied to SR data:

| Window      | Main Lobe Width | Side Lobe Level | Use Case                       |
|-------------|-----------------|-----------------|--------------------------------|
| Hann        | 4 bins          | -31 dB          | General purpose (standard)     |
| Hamming     | 4 bins          | -43 dB          | Better leakage suppression     |
| Blackman    | 6 bins          | -58 dB          | Strong nearby interference     |
| Kaiser (b=8)| 5 bins          | -50 dB          | Adjustable trade-off           |
| Rectangular | 2 bins          | -13 dB          | Not recommended for SR         |

The Hann window provides an acceptable trade-off between frequency resolution and spectral leakage for SR work. The rectangular (no window) case is not recommended due to severe spectral leakage that can obscure the weaker higher-order SR modes.

---

## 2. Parametric Spectral Fitting

### 2.1 Lorentzian Model

Each SR mode is well-approximated by a Lorentzian (Cauchy) distribution in the frequency domain, reflecting the resonant behavior of the Earth-ionosphere cavity (Sentman 1995). The composite model for all modes is:

    S(f) = sum_i [ A_i / ((f - f_i)^2 + (f_i / (2*Q_i))^2) ] + a*f + b

Where for each mode i:
- **A_i**: Amplitude parameter (proportional to peak power)
- **f_i**: Resonance frequency (Hz)
- **Q_i**: Quality factor (dimensionless, typically 3--8 for SR)
- **a*f + b**: Linear background model (noise floor)

This model captures 3 parameters per mode (A, f, Q) plus 2 global background parameters, giving 3N + 2 total parameters for N modes. For the standard 6 modes, this is 20 free parameters.

### 2.2 Levenberg-Marquardt Solver

The nonlinear least-squares fit of the Lorentzian model to the observed PSD is typically performed using the Levenberg-Marquardt (LM) algorithm, which interpolates between gradient descent and Gauss-Newton iteration:

**Algorithm outline:**
1. Compute Welch PSD estimate from time-domain data
2. Select frequency range (typically 3--45 Hz)
3. Initialize parameters from prior fit or literature values
4. Iterate LM solver until convergence (typical: 10--50 iterations)
5. Extract fitted parameters (f_i, Q_i, A_i) for each mode

**Initial parameter estimates (for cold start):**

| Mode | f_init (Hz) | Q_init | A_init (relative) |
|------|-------------|--------|--------------------|
| 1    | 7.83        | 5      | 1.0                |
| 2    | 14.1        | 5      | 0.5                |
| 3    | 20.3        | 5      | 0.3                |
| 4    | 26.4        | 5      | 0.15               |
| 5    | 32.5        | 5      | 0.08               |
| 6    | 38.0        | 5      | 0.04               |

For continuous monitoring, the previous time step's fitted parameters provide excellent initial estimates, dramatically improving convergence speed and robustness.

### 2.3 Goodness-of-Fit Metrics

Fit quality assessment is essential for automated processing:

- **Reduced chi-squared**: Should be near 1.0 for a good fit
- **Residual inspection**: Structured residuals indicate missing model components
- **Parameter bounds**: Fitted frequencies should remain within physically reasonable ranges (e.g., f_1 in 7.0--8.5 Hz)
- **Q-factor bounds**: Q values below 2 or above 12 are suspicious and may indicate fitting artifacts

---

## 3. Peak Detection Algorithms

### 3.1 Prominence-Based Detection

Direct peak detection on the PSD (without parametric fitting) uses prominence-based algorithms to identify SR modes:

1. **Local maxima identification**: Find all points where PSD(f_k) > PSD(f_{k-1}) and PSD(f_k) > PSD(f_{k+1})
2. **Prominence calculation**: For each local maximum, compute the height above the higher of the two surrounding minima
3. **Prominence threshold**: Retain only peaks with prominence exceeding a threshold (typically 2--3 sigma above the noise-estimated background)
4. **Mode assignment**: Associate detected peaks with expected SR modes based on proximity to nominal frequencies

### 3.2 Parabolic Interpolation

Discrete FFT/PSD bins do not generally coincide with the true SR peak frequencies. Parabolic (quadratic) interpolation of the three bins surrounding each detected peak provides sub-bin frequency accuracy:

    f_peak = f_k + (delta_f / 2) * (P_{k-1} - P_{k+1}) / (P_{k-1} - 2*P_k + P_{k+1})

Where P_k is the PSD value at bin k in dB (log) scale, and delta_f is the bin spacing. This typically improves frequency estimates by a factor of 5--10x relative to bin-center estimates, achieving accuracy of ~0.01 Hz with 0.1 Hz bin spacing.

### 3.3 Noise Floor Estimation via MAD

The Median Absolute Deviation (MAD) provides a robust estimate of the noise floor that is insensitive to the SR peaks themselves:

    noise_floor = median(|PSD - median(PSD)|) / 0.6745

The division by 0.6745 scales the MAD to be consistent with the standard deviation for Gaussian-distributed noise. This estimate is then used to set detection thresholds and assess signal-to-noise ratios for each SR mode.

---

## 4. Transient Event Detection: Q-Bursts

### 4.1 Definition and Significance

Q-bursts are transient enhancements of the SR field caused by exceptionally powerful lightning discharges (typically >250 kA return stroke current). They produce brief (0.3--1.5 seconds) amplitude excursions that can exceed the background SR level by an order of magnitude (Ogawa 1966; Sentman 1995).

### 4.2 Detection Criteria

Published Q-burst detection algorithms use amplitude and statistical thresholds:

**Amplitude threshold:**
- Peak amplitude exceeding 10x the running background level (Nickolaenko & Hayakawa 2002)
- This threshold balances detection sensitivity against false positive rate

**Core Standard Deviation (CSD) method:**
- Compute standard deviation in 5-second sliding segments
- Flag segments where CSD exceeds 16x the long-term baseline standard deviation
- This method is more robust to slow background variations than simple amplitude thresholds

### 4.3 Cross-Station Correlation

Q-bursts propagate at approximately the speed of light within the Earth-ionosphere waveguide and are observed quasi-simultaneously at all stations worldwide. Cross-station correlation provides:

1. **Confirmation**: A Q-burst must appear at multiple stations within 1--3 samples (at 100 Hz, this is 10--30 ms) to be confirmed
2. **Source localization**: Time-of-arrival differences across a station network can triangulate the source lightning stroke
3. **False positive rejection**: Local interference events will not correlate across distant stations

The 1--3 sample timing tolerance accounts for the finite propagation time across the Earth's surface (maximum ~67 ms for antipodal propagation) plus clock synchronization uncertainty.

### 4.4 Q-Burst Characterization

Once detected, Q-bursts are characterized by:
- Peak amplitude relative to background
- Duration (measured at half-maximum or some threshold above background)
- Spectral content (which SR modes are excited)
- Arrival time (GPS-referenced)
- Waveform shape (for propagation distance estimation)

---

## 5. Advanced Analytical Methods

### 5.1 Schumann Resonance Complexity Index (SRCI)

The SRCI quantifies the complexity of the SR signal using the H-rank algorithm, which is derived from singular value decomposition (SVD) of a Hankel matrix constructed from the time series:

**Algorithm:**
1. Construct a Hankel matrix from the SR time series
2. Compute the SVD of the Hankel matrix
3. Determine the effective rank (H-rank) using a threshold on the singular value ratio
4. The H-rank value serves as the complexity index

Higher SRCI values indicate more complex waveforms, which may reflect multiple active thunderstorm centers or ionospheric perturbations. SRCI has been proposed as a complementary metric to traditional amplitude and frequency parameters for characterizing the global lightning-ionosphere system.

### 5.2 Cross-Spectral Analysis

For multi-component or multi-station measurements:

- **Coherence**: Magnitude-squared coherence between orthogonal magnetic components or between stations indicates the degree of linear relationship as a function of frequency
- **Phase difference**: Intercomponent phase reveals polarization of the SR field, which carries information about the spatial distribution of lightning sources
- **Transfer functions**: Station-to-station transfer functions can identify local site effects and validate data quality

### 5.3 Time-Frequency Analysis

SR parameters vary on timescales from minutes (weather) to hours (diurnal cycle) to months (seasonal). Time-frequency representations capture this:

- **Spectrogram**: Short-time Fourier transform with sliding analysis window
- **Wavelet analysis**: Continuous wavelet transform provides adaptive time-frequency resolution
- **Hilbert-Huang Transform**: Empirical mode decomposition followed by Hilbert spectral analysis, applicable to non-stationary SR data

---

## 6. Machine Learning Approaches

### 6.1 Hybrid Deep Learning Autoencoder (2025)

Recent work (Debnath 2024) has applied hybrid deep learning architectures to SR signal processing, combining:

1. **Denoising autoencoder**: Trained on paired clean/noisy SR spectrograms to suppress interference while preserving SR structure
2. **Mode regression network**: A supervised network that estimates SR mode parameters (frequency, amplitude, Q-factor) directly from the denoised spectrogram

This end-to-end approach bypasses traditional PSD estimation and Lorentzian fitting, potentially offering:
- Robustness to non-Gaussian interference that violates Welch/multitaper assumptions
- Lower latency for real-time applications
- Graceful degradation under poor SNR conditions

### 6.2 Other ML Applications

Additional machine learning methods documented or proposed for SR:
- **Random forests** for SR mode classification under variable noise conditions
- **LSTM networks** for SR parameter prediction/nowcasting
- **Anomaly detection** (isolation forests, autoencoders) for identifying unusual SR behavior potentially linked to geophysical events
- **Gaussian process regression** for interpolating SR parameters across spatial gaps in the observatory network

---

## 7. Processing Pipeline Architecture

A typical end-to-end SR processing pipeline consists of:

```
Raw ADC data (100-256 Hz)
    |
    v
[DC removal + detrend]
    |
    v
[Digital notch filter: 50/60 Hz + harmonics]
    |
    v
[Bandpass filter: 3-45 Hz (4th order Butterworth)]
    |
    v
[Segment into 10-minute analysis windows]
    |
    v
[Welch PSD estimation (Hann, 10s segments, 50% overlap)]
    |
    v
[Noise floor estimation (MAD)]
    |
    v
[Peak detection (prominence-based + parabolic interpolation)]
    |
    v
[Lorentzian fitting (Levenberg-Marquardt)]
    |
    v
[Q-burst detection (amplitude + CSD threshold)]
    |
    v
[Parameter time series output: f_i(t), Q_i(t), A_i(t)]
    |
    v
[Archival and visualization]
```

### 7.1 Real-Time vs. Batch Processing

- **Real-time**: Streaming processing with 10-minute latency, suitable for monitoring and alerting
- **Batch**: Reprocessing of archived data with updated algorithms or parameters, suitable for research

Both modes should produce identical results when given identical input data, which requires careful handling of edge effects at analysis window boundaries.

### 7.2 Data Quality Flags

Automated QA/QC flags should accompany all processed output:

| Flag               | Condition                                    |
|--------------------|----------------------------------------------|
| CLEAN              | All modes detected, good fit quality         |
| NOISE_HIGH         | Background noise above threshold             |
| MODES_MISSING      | Fewer than 4 modes detected                  |
| FIT_POOR           | Reduced chi-squared > 3                      |
| INTERFERENCE       | Strong narrowband artifact detected          |
| Q_BURST            | Transient event detected in window           |
| DATA_GAP           | Missing samples in analysis window           |

---

## 8. Summary

SR signal processing is a mature field with well-established methods:

1. **Welch PSD** with Hann windows and 10-minute analysis windows is the observatory standard
2. **Multitaper methods** reduce variance and are preferred for short data segments
3. **Lorentzian fitting** with Levenberg-Marquardt extracts physically meaningful mode parameters
4. **Peak detection** with prominence thresholds and parabolic interpolation provides robust, non-parametric extraction
5. **Q-burst detection** requires amplitude (10x) and CSD (16x) thresholds with cross-station confirmation
6. **ML approaches** are emerging as complementary methods, particularly for denoising and parameter estimation under adverse conditions

The processing pipeline implemented in EarthSync follows these established methods while providing a modular architecture that can incorporate new techniques as they are validated.
