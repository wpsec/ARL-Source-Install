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
  const isSandstone = theme === 'sandstone';

  // 砂岩白主题单独优化可读性，其它深色主题统一高对比显示。
  const boxToneClass = isSandstone
    ? 'bg-gradient-to-br from-[#334155] via-[#2f3e57] to-[#1f2937] border border-black/15 shadow-[0_8px_22px_rgba(15,23,42,0.28)]'
    : 'bg-gradient-to-br from-[#2f7fff] via-[#4a8dff] to-[#67a7ff] border border-white/25 shadow-[0_10px_28px_rgba(46,130,255,0.5)]';
  const iconToneClass = isSandstone
    ? 'text-[#f8fafc] drop-shadow-[0_1px_3px_rgba(15,23,42,0.55)]'
    : 'text-fixed-white drop-shadow-[0_1px_4px_rgba(21,69,152,0.55)]';
  const overlayClass = isSandstone
    ? 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/20 via-white/8 to-transparent pointer-events-none'
    : 'absolute inset-0 rounded-[inherit] bg-gradient-to-tr from-white/30 via-white/12 to-transparent pointer-events-none';
  const beaconClass = isSandstone
    ? 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#f59e0b] border border-[#fef3c7]'
    : 'absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#7dd3fc] border border-[#dbeafe]';
  const arlTextClass = isSandstone
    ? 'text-[#1f2937] drop-shadow-[0_1px_0_rgba(255,255,255,0.45)]'
    : 'text-fixed-white drop-shadow-[0_2px_6px_rgba(0,0,0,0.25)]';
  const subTextClass = isSandstone ? 'text-[#57534e]' : 'text-[#c5e2ff]';

  return (
    <div className={`flex items-center ${cls.gap} ${className}`.trim()}>
      <div className="relative shrink-0">
        <div className={`${cls.box} ${boxToneClass} flex items-center justify-center overflow-hidden`}>
          <svg viewBox="0 0 24 24" className={`${cls.icon} ${iconToneClass} fill-current`}>
            <path d="M12 2L9 4v2h6V4l-3-2zm-2 5h4l1 12H9l1-12zm-1 14h6v1H9v-1z" />
            <circle cx="12" cy="9" r="1.5" className={iconToneClass} />
          </svg>
          <div className={overlayClass} />
        </div>
        <span className={beaconClass} />
      </div>
      <div className="flex flex-col min-w-0">
        <span className={`${cls.arl} font-black tracking-tight leading-none ${arlTextClass}`}>ARL</span>
        <span className={`${cls.sub} font-black uppercase tracking-[0.24em] mt-1 ${subTextClass}`}>Lighthouse</span>
      </div>
    </div>
  );
}
