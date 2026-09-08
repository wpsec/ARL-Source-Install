import React from 'react';
import { useTheme } from '../context/ThemeContext';

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
  const { theme } = useTheme();
  const cls = sizeClassMap[size];
  const toneMap = {
    midnight: {
      boxToneClass: 'bg-gradient-to-br from-[#293845] via-[#1b2936] to-[#101923] border border-[#41566a]/45 shadow-[0_12px_26px_rgba(4,10,20,0.34)]',
      iconToneClass: 'text-[#eef6ff] drop-shadow-[0_1px_3px_rgba(0,0,0,0.42)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/10 via-white/4 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#6f8da4] border border-[#d4e0e5]',
      arlTextClass: 'text-[#eef5fb] drop-shadow-[0_2px_6px_rgba(0,0,0,0.22)]',
      subTextClass: 'text-[#aab8c1]',
    },
    slate: {
      boxToneClass: 'bg-gradient-to-br from-[#3a5567] via-[#263c4c] to-[#142331] border border-[#506c7c]/45 shadow-[0_12px_26px_rgba(8,16,28,0.34)]',
      iconToneClass: 'text-[#f1f8ff] drop-shadow-[0_1px_3px_rgba(0,0,0,0.38)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/12 via-white/5 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#7898ad] border border-[#dce6ea]',
      arlTextClass: 'text-[#eef5fa] drop-shadow-[0_2px_6px_rgba(0,0,0,0.18)]',
      subTextClass: 'text-[#b1bec6]',
    },
    nord: {
      boxToneClass: 'bg-gradient-to-br from-[#52666d] via-[#394b52] to-[#222b32] border border-[#657982]/38 shadow-[0_12px_26px_rgba(8,13,18,0.28)]',
      iconToneClass: 'text-[#f2f8fb] drop-shadow-[0_1px_3px_rgba(0,0,0,0.32)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/12 via-white/5 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#8aa5ad] border border-[#e6eef0]',
      arlTextClass: 'text-[#edf4f7] drop-shadow-[0_2px_6px_rgba(0,0,0,0.16)]',
      subTextClass: 'text-[#bac5c9]',
    },
    titanium: {
      boxToneClass: 'bg-gradient-to-br from-[#36393a] via-[#292b2d] to-[#202223] border border-[#494d50] shadow-[0_12px_28px_rgba(0,0,0,0.34)]',
      iconToneClass: 'text-[#f3f9ff] drop-shadow-[0_1px_3px_rgba(0,0,0,0.4)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/8 via-white/3 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#7893a8] border border-[#d8e2e7]',
      arlTextClass: 'text-[#dbe4e8] drop-shadow-[0_2px_6px_rgba(0,0,0,0.2)]',
      subTextClass: 'text-[#aab3ba]',
    },
    sandstone: {
      boxToneClass: 'bg-gradient-to-br from-[#6f655c] via-[#514941] to-[#38322d] border border-black/10 shadow-[0_8px_22px_rgba(41,32,24,0.18)]',
      iconToneClass: 'text-[#faf7f2] drop-shadow-[0_1px_3px_rgba(28,25,23,0.4)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/18 via-white/8 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#b8946b] border border-[#eadcc9]',
      arlTextClass: 'text-[#3b352f] drop-shadow-[0_1px_0_rgba(255,255,255,0.45)]',
      subTextClass: 'text-[#756d65]',
    },
  } as const;
  const tone = toneMap[theme];

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
