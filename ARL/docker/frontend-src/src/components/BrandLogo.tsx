import React from 'react';

type BrandLogoSize = 'md' | 'lg';

interface BrandLogoProps {
  size?: BrandLogoSize;
  className?: string;
}

const sizeClassMap: Record<BrandLogoSize, { box: string; icon: string; arl: string; sub: string; gap: string }> = {
  md: {
    box: 'w-12 h-12 rounded-2xl',
    icon: 'w-8 h-8',
    arl: 'text-2xl',
    sub: 'text-[10px]',
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
  const cls = sizeClassMap[size];

  return (
    <div className={`flex items-center ${cls.gap} ${className}`.trim()}>
      <div className="relative shrink-0">
        <div
          className={`${cls.box} bg-gradient-to-br from-[#2f7fff] via-[#4a8dff] to-[#67a7ff] border border-white/25 flex items-center justify-center shadow-[0_8px_28px_rgba(46,130,255,0.5)] overflow-hidden`}
        >
          <svg viewBox="0 0 24 24" className={`${cls.icon} text-fixed-white fill-current drop-shadow-[0_0_10px_rgba(255,255,255,0.9)]`}>
            <path d="M12 2L9 4v2h6V4l-3-2zm-2 5h4l1 12H9l1-12zm-1 14h6v1H9v-1z" />
            <circle cx="12" cy="9" r="1.5" className="text-fixed-white" />
          </svg>
          <div className="absolute inset-0 bg-gradient-to-tr from-white/30 to-transparent pointer-events-none" />
        </div>
        <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#7dd3fc] border border-[#dbeafe]" />
      </div>
      <div className="flex flex-col min-w-0">
        <span className={`${cls.arl} font-black tracking-tight leading-none text-fixed-white`}>ARL</span>
        <span className={`${cls.sub} font-black uppercase tracking-[0.26em] mt-1 text-[#b8dcff]`}>Lighthouse</span>
      </div>
    </div>
  );
}
