import React from 'react';

type BrandLogoSize = 'md' | 'lg';

interface BrandLogoProps {
  size?: BrandLogoSize;
  className?: string;
}

const sizeClassMap: Record<BrandLogoSize, { box: string; icon: string; arl: string; sub: string; gap: string }> = {
  md: {
    box: 'w-12 h-12 rounded-box',
    icon: 'w-8 h-8',
    arl: 'text-[1.65rem]',
    sub: 'text-[11px]',
    gap: 'gap-4',
  },
  lg: {
    box: 'w-14 h-14 rounded-box',
    icon: 'w-9 h-9',
    arl: 'text-3xl',
    sub: 'text-xs',
    gap: 'gap-5',
  },
};

export default function BrandLogo({ size = 'md', className = '' }: BrandLogoProps) {
  const cls = sizeClassMap[size];
  const tone = {
    boxToneClass: 'bg-gradient-to-br from-base-300 via-base-200 to-base-100 border border-base-300 shadow-lg',
    iconToneClass: 'text-base-content',
    overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-base-content/10 via-base-content/5 to-transparent pointer-events-none',
    beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-accent border border-base-100',
    arlTextClass: 'text-base-content',
    subTextClass: 'text-base-content/70',
  };

  return (
    <div className={`flex items-center ${cls.gap} ${className}`.trim()}>
      <div className="relative shrink-0">
        <div className={`${cls.box} ${tone.boxToneClass} flex items-center justify-center overflow-hidden`}>
          <svg viewBox="0 0 24 24" className={`${cls.icon} ${tone.iconToneClass} fill-current`}>
            <path d="M12 2L9 4v2h6V4l-3-2zm-2 5h4l1 12H9l1-12zm-1 14h6v1H9v-1z" />
            <circle cx="12" cy="9" r="1.5" className={tone.iconToneClass} />
          </svg>
          <div className={tone.overlayClass} />
        </div>
        <span className={tone.beaconClass} />
      </div>
      <div className="flex flex-col min-w-0">
        <span className={`${cls.arl} font-black tracking-tight leading-none ${tone.arlTextClass}`}>ARL</span>
        <span className={`${cls.sub} font-black uppercase tracking-[0.24em] mt-1 ${tone.subTextClass}`}>Lighthouse</span>
      </div>
    </div>
  );
}
