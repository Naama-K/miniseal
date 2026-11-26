# MiniSeal: the product

**Prove a photo is yours, and that nobody has changed it, with one API call.**

## The problem

A regional news site publishes a photo of a flooded street. Two days later the
same photo is spreading on social media with the water edited higher and a
caption blaming the wrong city. Readers tag the newsroom and ask whether it's
real. The photo desk can only answer "trust us, ours was different". It has no
way to prove it.

AI image tools make this worse in both directions:

- Fake images look real.
- Real images get dismissed as fake ("that's AI").

Publishers need a way to say **"we published exactly these pixels, at this
time"** that anyone can check, without having to trust the publisher.

## The product

MiniSeal adds a cryptographic seal to an image when it's published, and gives
everyone else a public way to verify it.

- **Seal:** the publisher's system sends the image to `POST /seal` and gets back a sealed PNG
  and a `seal_id`. The seal is a signature over the image's pixels, stored inside the file.
- **Verify:** anyone uploads an image to `POST /verify` and gets one of three answers:
  - **intact:** sealed by a known publisher and not changed by a single pixel.
  - **tampered:** a seal is present, but the image or the seal was changed. The response says what failed.
  - **unsealed:** there's no seal. That isn't proof of a fake, only that there's no proof of origin.
- **Look up:** `GET /seals/{id}` shows who sealed the image and when.
- **Second opinion:** every verification also runs a content detector that scores how
  generated or edited the image looks. The seal proves where an image came from; the
  detector estimates whether the content is real. They answer different questions, so the
  response shows both.

## Who it's for

| Persona | Need | What they use |
|---|---|---|
| **Photo desk / publisher** (newsrooms, stock agencies) | Seal every image as part of publishing, without slowing it down | An API key and `/seal` from their CMS; `GET /seals` lists their own seals |
| **Fact-checker / journalist** | Check a viral image in seconds | The public web app, no account |
| **Platform trust & safety** | Label uploads automatically | `/verify` from their pipeline, reading the status and detector score |
| **Operator** | Manage keys and keep the service healthy | Key CLI, `/health`, `/ready`, Docker |

**The publisher is the paying customer, and verification is free.** The more people
verify, the more a seal is worth, which is why `/verify` needs no key.

## Why customers buy

| Pain | What MiniSeal gives them |
|---|---|
| "Our photos get doctored and we can't prove it." | Proof down to the pixel: changing even one pixel turns the answer into *tampered*. |
| "Readers say our real photos are AI fakes." | A public verify page to link from every article: "Check this photo yourself." |
| "We can't slow down publishing." | One REST call that returns a PNG which looks identical and opens in any viewer. |
| "We're afraid of putting our name on a fake by accident." | An optional policy that refuses to seal images the detector flags as suspicious. |
| "Security will ask hard questions." | Ed25519 signatures, API keys stored only as hashes, a registry where each customer sees only their own seals, a hardened container. |

## Design choices that follow from the customer

- **Verifying is public and needs no account.** A seal nobody can check is worthless.
- **A one-pixel change counts as tampered.** A newsroom's credibility rests on the exact pixels.
- **The output is always PNG.** Converting to a lossy format would make honest images fail.
- **The detector can't override the seal.** "We signed this" is a fact; "this looks
  generated" is a guess. If the detector fails, the seal answer still comes back.
- **Sealing suspicious images is the publisher's choice** (`reject_suspicious`), not ours.

## Questions customers ask

- **"Can't someone just strip the seal?"** Yes, and then the image reads as *unsealed*, never
  as *intact*. A seal can be removed but not forged. The planned pixel watermark will
  survive stripping.
- **"What if the image is recompressed when it's shared?"** Today it no longer matches
  exactly. The planned perceptual-hash match will report "derived from a sealed original".
- **"Isn't this just C2PA?"** It's the same idea, provenance as a signed record, offered as an
  API you can adopt in an afternoon, with verification and content scoring included.
- **"Is the detector reliable?"** It's a score shown next to the seal result, never instead
  of it. The customer sets the threshold based on what a false alarm costs them.

## What it doesn't do yet

- **Metadata stripping:** messaging apps and screenshots remove the seal.
- **Recompression:** a resized or recompressed copy no longer matches exactly.
- **Key custody:** the signing key isn't in a KMS or HSM yet, and there's no key rotation.

## Roadmap

1. Seal revocation ("we published this by mistake")
2. Per-key rate limits and usage metering, the basis for billing
3. A perceptual-hash "derived from sealed" verdict
4. A pixel watermark that survives metadata stripping
5. Postgres for seals and a log pipeline for analytics, for scale

## Pricing model (proposed)

| Plan | For | Includes |
|---|---|---|
| **Verify** | Everyone | Unlimited public verification, free |
| **Newsroom** | A single publication | Sealing up to a monthly quota, a dashboard of their own seals, one API key |
| **Enterprise** | Large publishers, platforms | High volume, multiple keys, seal revocation, an SLA, customer-managed keys |

## How we'd measure success

These are metrics to track, not results to claim:

- seals issued per publisher
- the share of verifications that come back intact, tampered or unsealed
- p95 latency of `/verify`
- the detector's false-positive rate on known-real images
