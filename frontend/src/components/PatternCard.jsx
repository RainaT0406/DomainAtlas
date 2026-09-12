function PatternCard({ value, label }) {
  return (
    <div className="pattern-card">
      <div className="pattern-value">
        {value}
      </div>

      <div className="pattern-label">
        {label}
      </div>
    </div>
  );
}

export default PatternCard;