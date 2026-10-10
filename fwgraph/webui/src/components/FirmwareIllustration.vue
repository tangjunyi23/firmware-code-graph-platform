<template>
  <div class="firmware-map" aria-hidden="true">
    <div class="map-caption"><span class="map-dot" /> FIRMWARE INTELLIGENCE <span>01 — 04</span></div>
    <svg viewBox="0 0 560 280" fill="none">
      <defs>
        <pattern id="fw-map-grid" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="#748ba8" opacity=".18" /></pattern>
        <linearGradient id="fw-map-edge" x1="40" y1="0" x2="520" y2="0" gradientUnits="userSpaceOnUse"><stop stop-color="#4f8cff"/><stop offset="1" stop-color="#39d3bd"/></linearGradient>
      </defs>
      <rect width="560" height="280" fill="url(#fw-map-grid)" />
      <circle cx="280" cy="141" r="110" stroke="#748ba8" stroke-opacity=".14" stroke-dasharray="4 8" />
      <g stroke="url(#fw-map-edge)" stroke-opacity=".6" stroke-width="1.5">
        <path d="M127 140H204M356 140H433M280 92V52H420V94M280 188V230H140V186" />
        <path d="M140 94V52H280M420 186V230H280" stroke-dasharray="4 6" />
      </g>
      <g fill="#112139" stroke="#335378">
        <rect x="204" y="92" width="152" height="96" rx="18" />
        <rect x="53" y="112" width="74" height="56" rx="12" />
        <rect x="433" y="112" width="74" height="56" rx="12" />
        <rect x="107" y="78" width="66" height="32" rx="8" />
        <rect x="387" y="78" width="66" height="32" rx="8" />
        <rect x="107" y="170" width="66" height="32" rx="8" />
        <rect x="387" y="170" width="66" height="32" rx="8" />
      </g>
      <g stroke="#7eacff" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
        <rect x="266" y="106" width="28" height="28" rx="6"/><rect x="273" y="113" width="14" height="14" rx="2"/>
        <path d="M271 102V106M280 102V106M289 102V106M271 134V138M280 134V138M289 134V138M262 111H266M262 120H266M262 129H266M294 111H298M294 120H298M294 129H298" />
        <path d="M81 130H98V151H81ZM85 136H94M85 141H94M85 146H91" />
        <path d="M470 128 482 133V142C482 149 470 154 470 154S458 149 458 142V133L470 128ZM465 141 469 145 476 137" stroke="#52d7c1" />
      </g>
      <g fill="#b8cce9" font-family="system-ui, sans-serif" font-size="10" text-anchor="middle">
        <text x="280" y="162" font-size="14" font-weight="600" fill="#edf4ff">代码知识图谱</text>
        <text x="140" y="99">函数</text><text x="420" y="99">入口</text>
        <text x="140" y="191">调用链</text><text x="420" y="191">风险</text>
        <text x="90" y="219">固件文件</text><text x="470" y="219">安全发现</text>
      </g>
      <g fill="#57d6c0"><circle cx="180" cy="140" r="3"/><circle cx="393" cy="140" r="3"/><circle cx="280" cy="52" r="3"/><circle cx="280" cy="230" r="3"/></g>
    </svg>
    <div class="map-footer"><span>解包与识别</span><i>→</i><span>代码与调用链</span><i>→</i><span>风险与验证</span></div>
  </div>
</template>
