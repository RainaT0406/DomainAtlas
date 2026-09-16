import { useEffect, useRef, useState } from "react";

export function useScanTimer(running) {
  const startTimeRef = useRef(null);
  const wasRunningRef = useRef(false);

  const [elapsed, setElapsed] = useState(0);
  const [finalTime, setFinalTime] = useState(0);

  useEffect(() => {
    // Scan has just started
    if (running && !wasRunningRef.current) {
      startTimeRef.current = Date.now();
      wasRunningRef.current = true;

      setElapsed(0);
      setFinalTime(0);
    }

    // Scan has just finished or stopped
    if (!running && wasRunningRef.current) {
      const finalElapsed =
        startTimeRef.current !== null
          ? Math.floor(
              (Date.now() - startTimeRef.current) / 1000
            )
          : 0;

      setElapsed(finalElapsed);
      setFinalTime(finalElapsed);

      startTimeRef.current = null;
      wasRunningRef.current = false;
    }
  }, [running]);

  useEffect(() => {
    if (!running || startTimeRef.current === null) {
      return undefined;
    }

    const interval = window.setInterval(() => {
      if (startTimeRef.current === null) {
        return;
      }

      const currentElapsed = Math.floor(
        (Date.now() - startTimeRef.current) / 1000
      );

      setElapsed(currentElapsed);
    }, 1000);

    return () => {
      window.clearInterval(interval);
    };
  }, [running]);

  return {
    elapsed,
    finalTime,
  };
}

export function formatScanTime(totalSeconds) {
  const seconds = Math.max(
    0,
    Math.floor(Number(totalSeconds) || 0)
  );

  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor(
    (seconds % 3600) / 60
  );
  const remainingSeconds = seconds % 60;

  if (hours > 0) {
    return `${String(hours).padStart(2, "0")}:${String(
      minutes
    ).padStart(2, "0")}:${String(
      remainingSeconds
    ).padStart(2, "0")}`;
  }

  return `${String(minutes).padStart(2, "0")}:${String(
    remainingSeconds
  ).padStart(2, "0")}`;
}