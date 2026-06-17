
# mkqhs

> **Work in progress.**

Research implementation of multi-key homomorphic signature (MKHS) schemes.
The main contribution is $\textsf{mkqhs}$ (`mkqhs_cbr_msq`), a multi-key
quadratic homomorphic signature scheme supporting bounded-rank quadratic functions with
message-squares. It builds on the baseline $\textsf{mklhs}$ scheme of Aranha and Pagnin
([ePrint 2019/830](https://eprint.iacr.org/2019/830)).

**Research artifact. Not audited. Do not use in production.**

## Built Directly Upon:

> Aranha, D. F., & Pagnin, E.
> _The Simplest Multi-key Linearly Homomorphic Signature Scheme_
> IACR Cryptology ePrint Archive, Paper 2019/830
> https://eprint.iacr.org/2019/830

## Schemes

The paper presents two schemes: $\textsf{mklhs}$ as the baseline and $\textsf{mkqhs}$ as the
main contribution. The intermediate constructions (`mkqhs_br`, `mkqhs_cbr`, `mkqhs_br_msq`) are
stepping stones not named in the paper.

| Module          | Scheme                                                                              | Function class | Eval. sig. size | Status      |
| --------------- | ----------------------------------------------------------------------------------- | -------------- | --------------- | ----------- |
| `mklhs`         | $\textsf{mklhs}$: Multi-key linearly homomorphic signatures (Aranha–Pagnin 2019)    | (0)            | $O(t)$          | implemented |
| `mkqhs_br`      | Bounded-rank quadratic, baseline (intermediate)                                     | (1)            | $O(tR)$         | skeleton    |
| `mkqhs_cbr`     | Bounded-rank quadratic, compressed (intermediate)                                   | (1)            | $O(t+R)$        | skeleton    |
| `mkqhs_br_msq`  | Bounded-rank quadratic with message-squares, baseline (intermediate)                | (2)            | $O(tR)$         | implemented |
| `mkqhs_cbr_msq` | $\textsf{mkqhs}$: Bounded-rank quadratic with message-squares, compressed           | (2)            | $O(t+R)$        | implemented |

$\textsf{mkqhs}$ is secure under the co-CDH\* assumption in the Type-3 pairing setting. The
evaluated signature size is reported in the number of signers $t$ and the bounded rank $R$.
Succinctness requires $R$ to grow at most logarithmically in the number of message inputs.

### Function Class (0)

Linear functions, as supported by the baseline `mklhs` scheme:

$$f(m_1,\ldots,m_n)=
\sum_{i=1}^n a_i m_i.
$$

### Function Class (1)

Bounded-rank quadratics, where the quadratic part is a sum of $R$ products of linear polynomials (and hence has _rank_ $R$):

$$f(m_1,\ldots,m_n)=
\sum_{i=1}^n a_i m_i
+
\sum_{r=1}^{R}
\Bigl(\sum_{i=1}^n u_{i,r}\,m_i\Bigr)
\Bigl(\sum_{i=1}^n v_{i,r}\,m_i\Bigr).
$$

### Function Class (2)

Message-squares extensions, which additionally admits direct
square terms $b_i m_i^2$ by having each signer also sign $m_i^2$:

$$f(m_1,\ldots,m_n)=
\sum_{i=1}^n\bigl(a_i m_i + b_i m_i^2\bigr)
+
\sum_{r=1}^{R}
\Bigl(\sum_{i=1}^n u_{i,r}\,m_i\Bigr)
\Bigl(\sum_{i=1}^n v_{i,r}\,m_i\Bigr).$$

## Examples

The `examples/` crate contains runnable demonstrations of `mkqhs_cbr_msq` on real data.

```
cargo example <name>
```

| Example              | Scheme         | Description                                                                                |
| -------------------- | -------------- | ------------------------------------------------------------------------------------------ |
| `variance`           | $\textsf{mkqhs}$ | Verifiable variance of the diabetes target variable across 10 signers                      |
| `euclidean_distance` | $\textsf{mkqhs}$ | Verifiable squared Euclidean distance between two randomly sampled patients (age, bmi, bp) |

### Dataset

Both examples use the [Efron–Hastie diabetes dataset](https://www4.stat.ncsu.edu/~boos/var.select/diabetes.html). On first run the file is downloaded and cached at `examples/data/diabetes.data`.

## Benchmarks

The `benches/` directory contains [Criterion](https://crates.io/crates/criterion)
benchmarks. The cycle-count benchmarks measure CPU cycles via
[`criterion-cycles-per-byte`](https://crates.io/crates/criterion-cycles-per-byte), so they
should be run with a stable clock (no Turbo Boost, single core, etc.) for accurate values.

```
cargo bench --bench <name>
```

| Bench                  | Scheme          | Measures                                                                                                                                                 |
| ---------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mklhs_cycles`         | $\textsf{mklhs}$         | CPU cycles for `keygen`, `sign`, `eval`, `verify` over $t \in$ {2, 5, 10} signers, each user signing 16 messages.                                      |
| `mkqhs_cbr_msq_cycles` | $\textsf{mkqhs}$ | CPU cycles for `keygen`, `sign`, `eval`, `verify` over $t \in$ {2, 5, 10} signers, each user signing 16 messages, swept over ranks $R \in$ {0,1,2,4,8} |
| `artifact_sizes`       | both            | Compressed byte sizes of keys, fresh signatures, and eval signatures                                                                                     |

Criterion writes HTML reports to `target/criterion/`.

## Dependencies

Built on [arkworks](https://arkworks.rs) with BLS12-381.
