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
      boxToneClass: 'bg-gradient-to-br from-[#22324a] via-[#152338] to-[#0b1220] border border-[#36516e]/45 shadow-[0_12px_26px_rgba(4,10,20,0.44)]',
      iconToneClass: 'text-[#eef6ff] drop-shadow-[0_1px_3px_rgba(0,0,0,0.42)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/10 via-white/4 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#5a94cb] border border-[#d7e9f8]',
      arlTextClass: 'text-[#eef5fb] drop-shadow-[0_2px_6px_rgba(0,0,0,0.22)]',
      subTextClass: 'text-[#a4b8cc]',
    },
    slate: {
      boxToneClass: 'bg-gradient-to-br from-[#2b4a68] via-[#1d3248] to-[#102031] border border-[#426584]/45 shadow-[0_12px_26px_rgba(8,16,28,0.42)]',
      iconToneClass: 'text-[#f1f8ff] drop-shadow-[0_1px_3px_rgba(0,0,0,0.38)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/12 via-white/5 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#63a4d6] border border-[#dff0ff]',
      arlTextClass: 'text-[#eef5fa] drop-shadow-[0_2px_6px_rgba(0,0,0,0.18)]',
      subTextClass: 'text-[#b1c4d4]',
    },
    nord: {
      boxToneClass: 'bg-gradient-to-br from-[#4a6172] via-[#314352] to-[#1b242e] border border-[#5a7488]/38 shadow-[0_12px_26px_rgba(8,13,18,0.34)]',
      iconToneClass: 'text-[#f2f8fb] drop-shadow-[0_1px_3px_rgba(0,0,0,0.32)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/12 via-white/5 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#79a8c3] border border-[#ebf5fb]',
      arlTextClass: 'text-[#edf4f7] drop-shadow-[0_2px_6px_rgba(0,0,0,0.16)]',
      subTextClass: 'text-[#b8c7d0]',
    },
    titanium: {
      boxToneClass: 'bg-gradient-to-br from-[#323233] via-[#252526] to-[#1e1e1e] border border-[#3c3c3c] shadow-[0_12px_28px_rgba(0,0,0,0.42)]',
      iconToneClass: 'text-[#f3f9ff] drop-shadow-[0_1px_3px_rgba(0,0,0,0.4)]',
      overlayClass: 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/8 via-white/3 to-transparent pointer-events-none',
      beaconClass: 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#3794ff] border border-[#d8eeff]',
      arlTextClass: 'text-[#dcebff] drop-shadow-[0_2px_6px_rgba(0,0,0,0.24)]',
      subTextClass: 'text-[#9eafbf]',
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
