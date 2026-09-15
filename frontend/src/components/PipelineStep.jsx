import {
  CheckCircle2,
  CircleDot,
  Loader2,
  Square,
} from "lucide-react";

function PipelineStep({
  label,
  message,
  status,
  isCancelled = false,
}) {
  const cancelled =
    status === "cancelled" ||
    isCancelled;

  const completed =
    status === "completed" &&
    !cancelled;

  const running =
    status === "running" &&
    !cancelled;

  let stateClass = "";

  if (cancelled) {
    stateClass = "cancelled";
  } else if (completed) {
    stateClass = "completed";
  } else if (running) {
    stateClass = "running";
  }

  let displayText = "Waiting";

  if (cancelled) {
    displayText = "Cancelled";
  } else if (completed) {
    displayText = "Complete";
  } else if (running) {
    displayText =
      message ||
      "Processing...";
  }

  return (
    <div
      className={`pipeline-step ${stateClass}`}
    >
      <div className="pipeline-step-icon">

        {completed ? (
          <CheckCircle2
            size={16}
          />
        ) : running ? (
          <Loader2
            size={16}
            className="spin"
          />
        ) : cancelled ? (
          <Square
            size={16}
          />
        ) : (
          <CircleDot
            size={16}
          />
        )}

      </div>

      <div className="pipeline-step-content">

        <strong>
          {label}
        </strong>

        <span>
          {displayText}
        </span>

      </div>

      <div className="pipeline-step-progress">

        {completed
          ? "✓"
          : cancelled
          ? "✕"
          : running
          ? "●"
          : "—"}

      </div>

    </div>
  );
}

export default PipelineStep;