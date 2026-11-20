// A circuit trace entering and leaving a shield, rendered locally at every resolution.
export default function SignalArt() {
  return (
    <svg
      className="hero-art"
      viewBox="0 0 520 180"
      preserveAspectRatio="xMaxYMid slice"
      aria-hidden="true"
    >
      <defs>
        <pattern id="trace-grid" width="20" height="20" patternUnits="userSpaceOnUse">
          <path d="M20 0H0V20" fill="none" stroke="#76bba3" strokeOpacity=".14" />
        </pattern>
        <linearGradient id="fade">
          <stop stopColor="white" stopOpacity="0" />
          <stop offset=".32" stopColor="white" />
        </linearGradient>
        <mask id="grid-mask">
          <rect width="520" height="180" fill="url(#fade)" />
        </mask>
      </defs>
      <g mask="url(#grid-mask)">
        <rect width="520" height="180" fill="url(#trace-grid)" />
        <g fill="none" stroke="#497d69" strokeWidth="1.2">
          <path d="M-15 24h115l52 52h98m-230-26h74l49 49h107M0 161h95l44-44h111M110 0v18l45 44h104M30 183h105l49-49h83M330 65h58l32-32h110M345 83h90l22-22h75M352 100h70l38 38h70M335 118h47l46 46h100M320 138l65 65" />
          <path stroke="#79d7ac" d="M37 98h63l15 15h52l23-23h60m92 0h57l17-17h51" />
        </g>
        {[0, 1, 2].map((i) => (
          <path
            key={i}
            d="M243 71l54-27 54 27v35l-54 28-54-28z"
            transform={`translate(0,${14 - i * 7})`}
            fill={i === 2 ? "#224839" : "#182e28"}
            stroke={i === 2 ? "#74b698" : "#406e58"}
          />
        ))}
        <path
          d="M272 87l22-12 24 5-1 14c-3 6-11 12-23 16-10-2-18-9-22-23z"
          fill="#35614d"
          stroke="#a5e5bc"
          strokeWidth="2"
        />
        <path d="m284 92 9 4 13-12" fill="none" stroke="#befad0" strokeWidth="2.5" />
        {[
          [37, 98],
          [100, 24],
          [167, 113],
          [467, 73],
          [435, 83],
          [428, 164],
          [95, 161],
        ].map(([x, y]) => (
          <circle key={x} cx={x} cy={y} r="3" stroke="#83c9aa" fill="#1a352a" />
        ))}
      </g>
    </svg>
  );
}
