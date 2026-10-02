import { useSyncExternalStore } from 'react';
import { getState, subscribe } from './store';

export function useStore() {
  return useSyncExternalStore(subscribe, getState, getState);
}
