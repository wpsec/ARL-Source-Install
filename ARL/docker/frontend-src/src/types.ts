export interface Asset {
  id: string;
  domain: string;
  ip: string;
  port: number;
  service: string;
  status: 'active' | 'inactive' | 'vulnerable';
  lastScan: string;
  tags: string[];
}

export interface ScanTask {
  id: string;
  target: string;
  progress: number;
  status: 'running' | 'completed' | 'failed';
  startTime: string;
}

export interface Stats {
  totalAssets: number;
  activeTasks: number;
  vulnerabilities: number;
  newAssetsToday: number;
}
