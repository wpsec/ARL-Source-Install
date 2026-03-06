import React, { createContext, useContext, useState, useEffect } from 'react';

export type ThemeType =
  | 'midnight'
  | 'slate'
  | 'nord'
  | 'titanium'
  | 'sandstone'
  | 'deepsea'
  | 'forest'
  | 'crimson'
  | 'cyberpunk'
  | 'minimalist';

interface ThemeContextType {
  theme: ThemeType;
  setTheme: (theme: ThemeType) => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // 默认主题与参考 UI 保持一致，减少首次加载视觉跳变
  const [theme, setThemeState] = useState<ThemeType>(() => {
    const saved = localStorage.getItem('arl-theme');
    return (saved as ThemeType) || 'nord';
  });

  const setTheme = (newTheme: ThemeType) => {
    setThemeState(newTheme);
    localStorage.setItem('arl-theme', newTheme);
  };

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) throw new Error('useTheme must be used within ThemeProvider');
  return context;
};
