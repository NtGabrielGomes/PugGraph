export const mapApi: {
  fit?: () => void;
  focus?: () => void;
  toggleConnect?: () => void;
  cancelConnect?: () => void;

  centerOn?: (id: string) => void;
  clearSelection?: () => void;
  connectFrom?: (id: string) => void;
  exportImage?: () => void;
  autoArrange?: () => void;
} = {};
