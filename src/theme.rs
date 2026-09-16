use std::sync::OnceLock;

use ratatui::style::Color;

/* A palette is a set of roles, not a set of pigments. The names used to be
   the colours themselves — CREAM, GOLD — which reads fine on one warm dark
   theme and lies on every other: a light theme's "cream" is near-black ink.
   What each slot is *for* is the part that survives a theme change, so that
   is what they are called. */
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Palette {
    /// Entry titles and anything the eye should land on first.
    pub text: Color,
    /// Chrome that should read as chrome: borders, bars, key names.
    pub accent: Color,
    /// Where the cursor is, and work that came out right.
    pub cursor: Color,
    /// Something to look at but not an error.
    pub warn: Color,
    /// A real failure.
    pub error: Color,
    /// Secondary text: usernames, urls, hints.
    pub muted: Color,
    /// Structure that must not compete with the list.
    pub rule: Color,
    /// Popups sit above the gradient, so they need one flat tone of their own
    /// or they read as a hole rather than a raised surface.
    pub surface: Color,
    /// Masked secrets and other text that is deliberately unreadable.
    /* Unused today — the masks draw in `muted`. Kept: it is the slot for
       "readable-but-not-text", the natural colour for a masked field. */
    #[allow(dead_code)]
    pub masked: Color,
    /// Text on a filled band, where the gradient is covered.
    /* Unused today — no filled band draws. Kept with the palette for the same
       reason the gradient sits in one file: a future banner should not invent
       its own ink. */
    #[allow(dead_code)]
    pub ink: Color,
    /* The diagonal gradient behind everything, as its two ends. Part of the
       palette because a light theme is not a light palette over a dark
       ground: they move together or nothing is legible. */
    pub near: (u8, u8, u8),
    pub far: (u8, u8, u8),
    /// Where the gradient stop sits: past it the whole corner is flat `far`.
    pub stop: f32,
}

/* Warm cream-on-dark: gold carries structure, teal marks where you are, and
   everything secondary is a muted sand rather than a grey. Text and ground
   are both warm, so the one cool colour is what the eye lands on. Every
   colour clears 4.5:1 over the lightest corner of the gradient except `rule`,
   which is meant to be barely there.

   The gradient is the hues of
   linear-gradient(45deg, hsla(10,19%,36%,1) 0%, hsla(290,95%,9%,1) 76%) at
   half brightness, so text stays the brightest thing on screen. */
pub const WARM: Palette = Palette {
    text: Color::Rgb(236, 223, 192),
    /* Darker than the text on purpose: the two were 1.13:1 apart before and
       read as one. */
    accent: Color::Rgb(214, 180, 96),
    // Cool against the warm ground, so it separates from warn by hue.
    cursor: Color::Rgb(96, 178, 158),
    warn: Color::Rgb(214, 154, 78),
    error: Color::Rgb(196, 106, 92),
    muted: Color::Rgb(158, 148, 128),
    rule: Color::Rgb(92, 84, 66),
    surface: Color::Rgb(46, 41, 33),
    masked: Color::Rgb(168, 155, 126),
    ink: Color::Rgb(24, 18, 16),
    near: (55, 40, 37),
    far: (18, 1, 22),
    stop: 0.76,
};

impl Palette {
    /* Every slot with its name, so a check that must cover the palette cannot
       quietly miss one: adding a field to the struct without adding it here
       is the mistake this exists to make hard. */
    /* Test-only until the contrast harness lands beside it (wave 2 of
       docs/theme-selection-plan.md), which is its real caller. */
    #[cfg(test)]
    pub fn slots(&self) -> [(&'static str, Color); 10] {
        [
            ("text", self.text),
            ("accent", self.accent),
            ("cursor", self.cursor),
            ("warn", self.warn),
            ("error", self.error),
            ("muted", self.muted),
            ("rule", self.rule),
            ("surface", self.surface),
            ("masked", self.masked),
            ("ink", self.ink),
        ]
    }
}

impl Default for Palette {
    fn default() -> Self {
        WARM
    }
}

impl Palette {
    pub fn background(&self, col: u16, row: u16, width: u16, height: u16) -> Color {
    // A single-cell span has nowhere to fade, and 0/0 is not a ratio.
    let frac = |v: u16, span: u16| {
        if span <= 1 {
            0.0
        } else {
            f32::from(v.min(span - 1)) / f32::from(span - 1)
        }
    };
    /* Normalised in cell space rather than pixels: terminal cells are about
       twice as tall as they are wide, so a true 45° would barely tilt. */
    let axis = (frac(col, width) + (1.0 - frac(row, height))) / 2.0;
    let t = (axis / self.stop).min(1.0);
    let mix = |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * t).round() as u8;
        Color::Rgb(
            mix(self.near.0, self.far.0),
            mix(self.near.1, self.far.1),
            mix(self.near.2, self.far.2),
        )
    }
}

/* Every colour here is 24-bit, which a terminal that cannot do 24-bit renders
   by its own rules: the gradient turns to bands and cream can land on a grey
   that no longer reads as the brightest thing on screen. Resolved once and
   applied to the finished buffer, so the palette above stays one set of
   numbers rather than three. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Depth {
    Full,
    /// The xterm cube and its grey ramp, which is what `TERM=xterm-256color`
    /// promises without `COLORTERM`.
    Ansi256,
    /// NO_COLOR: the terminal's own two colours and nothing else.
    Plain,
}

/// Kept apart from the environment so the decision can be tested as the
/// decision it is, rather than as whatever the machine running the tests is.
pub fn depth_from(no_color: Option<&str>, colorterm: &str, term: &str) -> Depth {
    /* The convention is presence, not truth: any non-empty value means no
       colour, and setting it to "0" still means no. */
    if no_color.is_some_and(|v| !v.is_empty()) {
        return Depth::Plain;
    }
    let says = |v: &str, what: &str| v.to_lowercase().contains(what);
    if says(colorterm, "truecolor") || says(colorterm, "24bit") {
        return Depth::Full;
    }
    // Some terminals advertise it in TERM instead, and nowhere else.
    if says(term, "truecolor") || says(term, "direct") {
        return Depth::Full;
    }
    /* Assumed rather than detected, and deliberately the cautious way round:
       a truecolor terminal shown 256 colours loses some smoothness in the
       gradient, where the other way round loses the text. COLORTERM=truecolor
       is how to say otherwise. */
    Depth::Ansi256
}

pub fn depth() -> Depth {
    static DEPTH: OnceLock<Depth> = OnceLock::new();
    *DEPTH.get_or_init(|| {
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        depth_from(
            std::env::var("NO_COLOR").ok().as_deref(),
            &var("COLORTERM"),
            &var("TERM"),
        )
    })
}

/// Whether colour is switched off altogether, which the widgets that paint a
/// background have to know: reversed video is what carries a filled band when
/// there is no colour to fill it with.
pub fn plain() -> bool {
    depth() == Depth::Plain
}

/// The xterm ramp, which is not linear: the first step is 95, not 51.
const RAMP: [u8; 6] = [0, 95, 135, 175, 215, 255];

fn nearest(value: u8, to: &[u8]) -> usize {
    to.iter()
        .enumerate()
        .min_by_key(|(_, v)| i16::from(**v).abs_diff(i16::from(value)))
        .map_or(0, |(at, _)| at)
}

/// The nearest of the 216-colour cube and the 24-step grey ramp, whichever is
/// closer: the greys are far finer than the cube, and most of this palette is
/// a near-grey.
pub fn quantise(r: u8, g: u8, b: u8) -> Color {
    let cube = [nearest(r, &RAMP), nearest(g, &RAMP), nearest(b, &RAMP)];
    let cube_rgb = [RAMP[cube[0]], RAMP[cube[1]], RAMP[cube[2]]];

    let grey_at = |n: usize| 8 + 10 * n as u8;
    let greys: Vec<u8> = (0..24).map(grey_at).collect();
    let grey = nearest(((u16::from(r) + u16::from(g) + u16::from(b)) / 3) as u8, &greys);
    let grey_rgb = [greys[grey]; 3];

    let apart = |a: [u8; 3]| {
        [(a[0], r), (a[1], g), (a[2], b)]
            .iter()
            .map(|(x, y)| u32::from(x.abs_diff(*y)).pow(2))
            .sum::<u32>()
    };
    if apart(grey_rgb) < apart(cube_rgb) {
        Color::Indexed(232 + grey as u8)
    } else {
        Color::Indexed(16 + 36 * cube[0] as u8 + 6 * cube[1] as u8 + cube[2] as u8)
    }
}

pub fn shade_at(depth: Depth, color: Color) -> Color {
    match (depth, color) {
        (Depth::Full, _) => color,
        // Reset, not black: the terminal's own two colours are the point.
        (Depth::Plain, _) => Color::Reset,
        (Depth::Ansi256, Color::Rgb(r, g, b)) => quantise(r, g, b),
        (Depth::Ansi256, _) => color,
    }
}

/// What a colour becomes on this terminal.
pub fn shade(color: Color) -> Color {
    shade_at(depth(), color)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cube is coarse and the grey ramp is fine, and most of this palette
    /// sits nearer a grey than a cube corner.
    #[test]
    fn a_colour_lands_on_whichever_of_the_two_ramps_is_closer() {
        // Exactly a cube corner.
        assert_eq!(quantise(255, 0, 0), Color::Indexed(196));
        assert_eq!(quantise(0, 0, 0), Color::Indexed(16));
        // A near-grey: the cube would round it to 135,135,135 and lose it.
        assert_eq!(quantise(128, 128, 128), Color::Indexed(244));
        // Something saturated stays on the cube rather than going grey.
        let teal = quantise(96, 178, 158);
        assert!(
            matches!(teal, Color::Indexed(n) if (16..232).contains(&n)),
            "teal went grey: {teal:?}"
        );
    }

    /// Every index has to be one a terminal actually has.
    #[test]
    fn nothing_lands_outside_the_256_colours() {
        for r in (0..=255).step_by(17) {
            for g in (0..=255).step_by(17) {
                for b in (0..=255).step_by(17) {
                    match quantise(r, g, b) {
                        Color::Indexed(n) => assert!(n >= 16, "{r},{g},{b} hit a system colour"),
                        other => panic!("{r},{g},{b} gave {other:?}"),
                    }
                }
            }
        }
    }

    /* The cautious way round on purpose: a truecolor terminal shown 256
       colours loses smoothness, where the other way round loses the text. */
    #[test]
    fn the_depth_is_read_from_the_environment_the_way_round_that_is_safe() {
        assert_eq!(depth_from(None, "truecolor", "xterm"), Depth::Full);
        assert_eq!(depth_from(None, "24bit", "xterm"), Depth::Full);
        assert_eq!(depth_from(None, "", "xterm-direct"), Depth::Full);
        // 256color promises 256 and nothing more, whatever it can really do.
        assert_eq!(depth_from(None, "", "xterm-256color"), Depth::Ansi256);
        assert_eq!(depth_from(None, "", ""), Depth::Ansi256);

        // Presence, not truth: NO_COLOR=0 still means no colour.
        assert_eq!(depth_from(Some("1"), "truecolor", ""), Depth::Plain);
        assert_eq!(depth_from(Some("0"), "truecolor", ""), Depth::Plain);
        // An empty value is the one case that does not count.
        assert_eq!(depth_from(Some(""), "truecolor", ""), Depth::Full);
    }

    /// Back to RGB, for checking a quantised colour against the one it came
    /// from. The cube and the grey ramp have different formulas.
    fn rgb_of(color: Color) -> (u8, u8, u8) {
        let Color::Indexed(n) = color else {
            panic!("{color:?} is not an indexed colour");
        };
        if n >= 232 {
            let grey = 8 + 10 * (n - 232);
            return (grey, grey, grey);
        }
        let n = n - 16;
        (RAMP[n as usize / 36], RAMP[n as usize % 36 / 6], RAMP[n as usize % 6])
    }

    /* The palette is what has to survive the trip, not any colour: a cream
       that lands on a grey stops being the brightest thing on screen. */
    #[test]
    fn every_palette_colour_survives_the_256_colour_cube() {
        for (name, color) in WARM.slots() {
            let Color::Rgb(r, g, b) = color else {
                panic!("{name} is not an RGB colour");
            };
            let (qr, qg, qb) = rgb_of(shade_at(Depth::Ansi256, color));
            let off = r.abs_diff(qr).max(g.abs_diff(qg)).max(b.abs_diff(qb));
            assert!(off <= 20, "{name} moved {off} to ({qr},{qg},{qb})");
        }
    }

    /* The default palette is the one this app has always drawn in: the move
       to role names was a rename, and a rename that changes a colour is not a
       rename. Pinned by value so a future edit has to mean it. */
    #[test]
    fn the_default_palette_is_the_warm_one_unchanged() {
        assert_eq!(Palette::default(), WARM);
        assert_eq!(WARM.text, Color::Rgb(236, 223, 192));
        assert_eq!(WARM.accent, Color::Rgb(214, 180, 96));
        assert_eq!(WARM.cursor, Color::Rgb(96, 178, 158));
        assert_eq!(WARM.warn, Color::Rgb(214, 154, 78));
        assert_eq!(WARM.error, Color::Rgb(196, 106, 92));
        assert_eq!(WARM.muted, Color::Rgb(158, 148, 128));
        assert_eq!(WARM.rule, Color::Rgb(92, 84, 66));
        assert_eq!(WARM.surface, Color::Rgb(46, 41, 33));
        assert_eq!((WARM.near, WARM.far, WARM.stop), ((55, 40, 37), (18, 1, 22), 0.76));
    }

    /* The gradient reads off the palette now, so its ends have to be the
       palette's ends: a theme whose ground does not move with its ink is the
       one way a light theme becomes unreadable. */
    #[test]
    fn the_gradient_runs_between_the_palettes_own_stops() {
        // Bottom-left is `near`; the far corner is flat past the stop.
        assert_eq!(WARM.background(0, 9, 10, 10), Color::Rgb(55, 40, 37));
        assert_eq!(WARM.background(9, 0, 10, 10), Color::Rgb(18, 1, 22));
    }

    /// Every colour goes, so the words and the marks have to carry it.
    #[test]
    fn no_colour_leaves_nothing_for_a_terminal_to_render() {
        for (name, color) in WARM.slots() {
            assert_eq!(shade_at(Depth::Plain, color), Color::Reset, "{name} kept its colour");
        }
        assert_eq!(shade_at(Depth::Plain, Color::Indexed(4)), Color::Reset);
        assert_eq!(shade_at(Depth::Full, WARM.text), WARM.text);
    }
}
