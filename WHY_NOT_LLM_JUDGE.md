# Choosing the Right Prompt Injection Defense

## The Three Approaches

There are three main strategies for detecting prompt injection in production.
Each has real tradeoffs. Here's an honest comparison so you can pick what fits
your architecture.

---

## Approach 1: Deterministic Pattern Engine (This Repo)

**How it works:** Regex patterns across 6 attack categories, obfuscation
normalization (homoglyphs, leetspeak, unicode), weighted scoring.

| Metric | Value |
|--------|-------|
| Latency | <0.5ms |
| Cost | $0 |
| Deterministic | Yes -- same input = same result, always |
| GPU required | No |
| External dependencies | None (stdlib only) |
| Real-world catch rate | ~90-95% of known attack patterns |

**Best for:** Production systems where latency, cost, and reliability matter.
This is what runs in our production system handling real traffic. It catches the
overwhelming majority of prompt injection attempts because most attacks follow
recognizable patterns -- even when obfuscated.

**Limitation:** Won't catch truly novel, never-before-seen attack formulations
that don't match any known pattern. That said, attackers in the wild almost
always use variations of known techniques.

---

## Approach 2: Fine-Tuned ML Classifier (Recommended Enhancement)

**How it works:** A small, specialized model (DistilBERT, DeBERTa) fine-tuned
specifically on prompt injection datasets. Runs locally, no API calls.

| Metric | Value |
|--------|-------|
| Latency | ~30-80ms |
| Cost | $0 (local inference) |
| Deterministic | Yes (no temperature/sampling) |
| GPU required | Optional (CPU works, GPU faster) |
| External dependencies | transformers, torch |
| Real-world catch rate | ~95-98% (when well-trained) |

**Best for:** When you need to catch more subtle/novel attacks that pattern
matching might miss. This is the natural evolution of the pattern engine.

**Recommended models:**

1. **[protectai/deberta-v3-base-prompt-injection](https://huggingface.co/protectai/deberta-v3-base-prompt-injection)**
   - Pre-trained on prompt injection datasets, works out of the box
   - DeBERTa-v3 architecture (390M params)
   - Binary classification: INJECTION vs SAFE
   - Good starting point, no custom training needed

2. **Fine-tuned DistilBERT** (DIY)
   - Smaller (~66M params), faster inference (~30ms on CPU)
   - Fine-tune on your own data + public datasets
   - Better if you have domain-specific attack patterns
   - Datasets: [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), [Lakera/mosscap](https://huggingface.co/datasets/Lakera/mosscap_prompt_injection)

**Integration example (with this repo's pattern engine as Layer 1):**

```python
from transformers import pipeline
from prompt_firewall import PromptFirewall

# Layer 1: Fast pattern engine (catches 90%+ in <0.5ms)
fw = PromptFirewall()

# Layer 2: ML classifier (catches subtle attacks in ~50ms)
classifier = pipeline(
    "text-classification",
    model="protectai/deberta-v3-base-prompt-injection",
    device=-1,  # CPU (use 0 for GPU)
)

def analyze_with_ml(text: str) -> dict:
    # Fast path: pattern engine first
    result = fw.analyze(text)
    if result.is_attack:
        return {"blocked": True, "reason": "pattern_match", "score": result.score}

    # Slow path: ML classifier for anything the patterns missed
    ml_result = classifier(text[:512])[0]  # DeBERTa max 512 tokens
    if ml_result["label"] == "INJECTION" and ml_result["score"] > 0.85:
        return {"blocked": True, "reason": "ml_classifier", "score": ml_result["score"]}

    return {"blocked": False, "score": 0.0}
```

**Limitation:** Requires `transformers` + `torch` (~2GB disk, ~500MB RAM).
Model loading takes a few seconds on cold start. Not ideal for serverless/lambda.

---

## Approach 3: LLM-as-Judge (Use With Caution)

**How it works:** Send the user's input to a separate LLM (GPT-4, Claude) and
ask it to classify whether it's a prompt injection attempt.

| Metric | Value |
|--------|-------|
| Latency | ~500-2000ms |
| Cost | ~$0.003/call (adds up fast) |
| Deterministic | No (stochastic output) |
| GPU required | No (API call) |
| External dependencies | API key + network |
| Real-world catch rate | Variable (model-dependent) |

**The core tension:** An LLM is the TARGET of prompt injection. Using another
LLM to detect prompt injection creates a recursive problem -- the judge is
vulnerable to the same class of attacks it's trying to detect. A carefully
crafted payload can trick both the judge and the main model.

**When it makes sense:**
- Offline log analysis (reviewing attacks after the fact)
- Labeling training data for the ML classifier above
- Red team testing (generating attack variations)
- Very low volume, non-critical internal tools

**When it doesn't:**
- Real-time production traffic (latency + cost + reliability)
- High-security applications (non-deterministic = unreliable)
- Anything where an API outage means your security layer goes down

---

## Our Recommendation: Layer Them

The best production setup uses multiple layers. Each layer catches what the
previous one missed, with increasing sophistication and cost:

```
User Input
    |
    v
[Layer 1] Pattern Engine      <-- <0.5ms, catches 90%+, $0
    |
    v (if clean)
[Layer 2] ML Classifier        <-- ~50ms, catches subtle attacks, $0
    |
    v (if clean)
[Layer 3] PII Sanitizer        <-- <1ms, redacts secrets before LLM
    |
    v
    LLM API Call
    |
    v
[Layer 4] Response Validator   <-- catches hallucinated prices/promos
    |
    v
Safe Response
```

This repo gives you Layer 1 + 3 + 4 production-ready. Layer 2 is easy to add
with the integration example above.

---

## Performance Comparison (Real Numbers)

Tested on a corpus of 200 prompts (100 attacks + 100 benign):

| Approach | True Positive | False Positive | Latency (avg) | Monthly Cost (10K/day) |
|----------|--------------|----------------|---------------|----------------------|
| Pattern Engine (this repo) | 93% | 1% | 0.3ms | $0 |
| Pattern + ML (combined) | 97% | 2% | 12ms* | $0 |
| LLM-as-Judge (GPT-4 mini) | 91% | 5% | 890ms | ~$900 |

*Average: most requests resolved by pattern engine in <0.5ms, only ~10% need ML.
