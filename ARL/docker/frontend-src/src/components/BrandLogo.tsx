import React from 'react';
import { useTheme } from '../context/ThemeContext';

type BrandLogoSize = 'md' | 'lg';

interface BrandLogoProps {
  size?: BrandLogoSize;
  className?: string;
}

const sizeClassMap: Record<BrandLogoSize, { box: string; icon: string; arl: string; sub: string; gap: string }> = {
  md: {
    box: 'w-12 h-12 rounded-2xl',
    icon: 'w-8 h-8',
    arl: 'text-[1.65rem]',
    sub: 'text-[11px]',
    gap: 'gap-4',
  },
  lg: {
    box: 'w-14 h-14 rounded-2xl',
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
      boxToneClass: 'bg-gradient-to-br from-[#2a313a] via-[#1e2731] to-[#121820] border border-white/10 shadow-[0_10px_24px_rgba(5,10,18,0.42)]',
      iconToneClass: 'text-[#f4f7fb] drop-shadow-[0_1px_3px_rgba(0,0,0,0.38)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/14 via-white/5 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#8fb4cf] border border-[#d9e4ed]',
      arlTextClass: 'text-[#edf2f6] drop-shadow-[0_2px_6px_rgba(0,0,0,0.2)]',
      subTextClass: 'text-[#afbbc7]',
    },
    slate: {
      boxToneClass: 'bg-gradient-to-br from-[#344255] via-[#263548] to-[#192433] border border-white/12 shadow-[0_10px_24px_rgba(12,18,30,0.4)]',
      iconToneClass: 'text-[#f4f8fb] drop-shadow-[0_1px_3px_rgba(0,0,0,0.34)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/16 via-white/6 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#9fbdcf] border border-[#d9e5ec]',
      arlTextClass: 'text-[#edf3f8] drop-shadow-[0_2px_6px_rgba(0,0,0,0.18)]',
      subTextClass: 'text-[#b9c9d6]',
    },
    nord: {
      boxToneClass: 'bg-gradient-to-br from-[#46515c] via-[#35404a] to-[#232b33] border border-white/12 shadow-[0_10px_24px_rgba(9,14,20,0.34)]',
      iconToneClass: 'text-[#f4f7f8] drop-shadow-[0_1px_3px_rgba(0,0,0,0.3)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/14 via-white/6 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#c8d9e3] border border-[#eef4f8]',
      arlTextClass: 'text-[#edf2f5] drop-shadow-[0_2px_6px_rgba(0,0,0,0.16)]',
      subTextClass: 'text-[#bdcad2]',
    },
    titanium: {
      boxToneClass: 'bg-gradient-to-br from-[#4d535a] via-[#353a41] to-[#21252b] border border-white/10 shadow-[0_10px_24px_rgba(5,7,10,0.42)]',
      iconToneClass: 'text-[#f3f4f5] drop-shadow-[0_1px_3px_rgba(0,0,0,0.34)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/10 via-white/4 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#d7dce1] border border-[#f5f7f8]',
      arlTextClass: 'text-[#e9edf0] drop-shadow-[0_2px_6px_rgba(0,0,0,0.2)]',
      subTextClass: 'text-[#b9c0c7]',
    },
    sandstone: {
      boxToneClass: 'bg-gradient-to-br from-[#4f473f] via-[#39322b] to-[#241f1a] border border-black/12 shadow-[0_8px_22px_rgba(41,32,24,0.22)]',
      iconToneClass: 'text-[#faf7f2] drop-shadow-[0_1px_3px_rgba(28,25,23,0.4)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/18 via-white/8 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#d19c5c] border border-[#f5dfbf]',
      arlTextClass: 'text-[#1f2937] drop-shadow-[0_1px_0_rgba(255,255,255,0.45)]',
      subTextClass: 'text-[#6b6258]',
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
