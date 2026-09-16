import { Clock } from "lucide-react";
import {
  formatScanTime,
} from "../utils/useScanTimer";

function ScanTimer({
  running = false,
  elapsed = 0,
  finalTime = 0,
  completed = false,
}) {
  // ============================================================
  // RUNNING DISPLAY
  // ============================================================

  if (running) {
    return (
      <div className="scan-time">
        <Clock size={16} />

        <div className="scan-time-content">
          <span>SCAN TIME</span>

          <strong>
            {formatScanTime(elapsed)}
          </strong>
        </div>
      </div>
    );
  }

  // ============================================================
  // COMPLETED DISPLAY
  // ============================================================

  if (completed) {
    return (
      <div className="analysis-complete">
        <Clock size={16} />

        <span>
          {formatScanTime(finalTime)}
        </span>

        <span>COMPLETE</span>
      </div>
    );
  }

  return null;
}

export default ScanTimer;