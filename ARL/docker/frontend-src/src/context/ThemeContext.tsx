import React, { createContext, useContext, useState, useEffect } from 'react';

export type ThemeType = 'midnight' | 'slate' | 'nord' | 'titanium' | 'sandstone';

interface ThemeContextType {
  theme: ThemeType;
  setTheme: (theme: ThemeType) => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);
const THEME_STORAGE_KEY = 'arl-theme';
const THEME_DEFAULT_MIGRATION_KEY = 'arl-theme-default-migrated-v1';

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // 默认主题改为钛金黑，并将历史主题值一次性迁移到 titanium
  const [theme, setThemeState] = useState<ThemeType>(() => {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    const validThemes: ThemeType[] = ['midnight', 'slate', 'nord', 'titanium', 'sandstone'];
    if (saved && validThemes.includes(saved as ThemeType)) {
      const migrated = localStorage.getItem(THEME_DEFAULT_MIGRATION_KEY) === '1';
      if (!migrated && saved !== 'titanium') {
        localStorage.setItem(THEME_STORAGE_KEY, 'titanium');
        localStorage.setItem(THEME_DEFAULT_MIGRATION_KEY, '1');
        return 'titanium';
      }
      return saved as ThemeType;
    }
    localStorage.setItem(THEME_DEFAULT_MIGRATION_KEY, '1');
    return 'titanium';
  });

  const setTheme = (newTheme: ThemeType) => {
    setThemeState(newTheme);
    localStorage.setItem(THEME_STORAGE_KEY, newTheme);
    localStorage.setItem(THEME_DEFAULT_MIGRATION_KEY, '1');
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
