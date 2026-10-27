<script>
  // The app icon's mark without its tile, so it sits on the page in either theme.
  let { width = 40, height = 46, closed = false } = $props();
  const uid = $props.id();
  const glow = `${uid}-glow`;
</script>

<svg class="mark" class:closed viewBox="230 192 564 640" {width} {height} aria-hidden="true">
  <defs>
    <radialGradient id={glow} cx=".5" cy=".58" r=".5">
      <stop offset="0" stop-opacity=".45" />
      <stop offset="1" stop-opacity="0" />
    </radialGradient>
  </defs>
  <polygon points="512,232 754.5,372 754.5,652 512,792 269.5,652 269.5,372" class="body" />
  <ellipse cx="512" cy="560" rx="200" ry="230" fill="url(#{glow})" />
  <polygon points="512,232 754.5,372 754.5,652 512,792 269.5,652 269.5,372" class="edge" />
  <g class="hole">
    <circle cx="512" cy="468" r="62" />
    <path d="M482 500 H542 L566 652 H458 Z" />
  </g>
</svg>

<style>
  .mark {
    flex: none;
  }

  stop {
    stop-color: var(--accent);
  }

  .body {
    fill: var(--panel);
  }

  .edge {
    fill: none;
    stroke: var(--accent-text);
    stroke-width: 34;
    stroke-linejoin: round;
  }

  .hole {
    fill: var(--accent-text);
    transform-box: fill-box;
    transform-origin: center;
    transition: transform 450ms cubic-bezier(0.5, 0, 0.2, 1);
  }

  .closed .hole {
    transform: scale(0.15);
  }

  @media (prefers-reduced-motion: reduce) {
    .hole {
      transition: none;
    }
  }
</style>
