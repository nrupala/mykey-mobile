# Design note — appearance, skins, and why they look the way they do

The web client's look is a system, not a coat of paint. Every
colour on every screen comes from a **theme token set**
(`src/ui/themes.ts`); components never hard-code a colour. A skin
is one complete token set plus a five-step strength-meter ramp,
and switching skins repaints the whole app instantly.

## Device first

On first run there is no skin choice at all: the app follows the
device. Light/dark comes from the operating system
(`prefers-color-scheme`, answered live if the OS flips), text is
sized in relative units throughout so the OS font-size setting
scales the whole UI (the Android shell sets no WebView text-zoom
override — the system font scale applies as the platform intends),
and `prefers-reduced-motion` disables transitions. Picking a skin
overrides the device; **Settings → Appearance → Use device
settings** hands control back.

The choice is a non-secret UI preference. It is stored in
localStorage so it can be applied before first paint — the app
never flashes the wrong colours.

## The skins

| Skin | Feel | Scheme |
|---|---|---|
| Device | Whatever the device says (Daylight / Midnight) | auto |
| Daylight | Bright, clear, well-lit desk | light |
| Midnight | Deep blue-dark for night use | dark |
| Ocean | Deep blue/teal — calm water | dark |
| Forest | Soft green light | light |
| Dune | Warm sand and amber | light |
| Chakra | Deep indigo; the seven-chakra spectrum as accent | dark |
| High Contrast | Black on white, maximum legibility | light |

## Why these colours (design intent)

- **Trust hues lead.** Blue and teal carry the primary actions in
  most skins: they read as calm, steady, and credible — the mood a
  password vault should project. Nothing about the interface
  shouts; surfaces stay low-saturation and quiet so the one
  primary button per screen is unmistakable.
- **Warm means caution, red means danger.** Amber appears only
  where the user should slow down. Red is reserved for true
  danger — deletion, and the one deliberately alarming screen in
  the app: the plain-text CSV export warning.
- **Confidence through consistency.** The sign-in-code green,
  the caution amber, and the danger red mean the same thing in
  every skin, so what a user learns in one skin stays true in
  another. Meaning never rides on colour alone: the strength
  meter pairs its segments with a word, and states are labelled.
- **Night skins are deep colour, not black.** Midnight, Ocean,
  and Chakra sit on deep blue/indigo rather than pure black, so
  light text does not smear or halo at night.
- **The Chakra skin** is the expressive option: a deep indigo
  base with accents drawn from the seven-chakra spectrum — root
  red, sacral orange, solar yellow, heart green, throat blue,
  third-eye indigo, crown violet — most visibly as the password
  strength meter's ramp (weakest → strongest follows the spectrum
  upward) and the picker's swatch band. It is offered because
  colour carries personal meaning for many users, and a vault you
  *like* opening is a vault you keep using. These are statements
  about design and mood only — the product makes no medical,
  healing, or spiritual claims.

## The accessibility gate

A skin that fails is not a skin. `tests/themes.test.ts` computes
WCAG contrast ratios for every text pair (≥ 4.5:1) and component
pair (≥ 3:1) in every palette, and CI fails the build on any
violation — the palettes in `themes.ts` are the values that pass.
Focus indicators are 3px and always visible, touch targets stay
large, and font scaling plus reduced motion work under every
skin.
