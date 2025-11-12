import React from 'react';

interface SeverityBadgeProps {
  level: 'Low' | 'Medium' | 'High' | 'Critical';
  className?: string;
}

export function SeverityBadge({ level, className = '' }: SeverityBadgeProps) {
  const colors = {
    Low: 'bg-green-500',
    Medium: 'bg-yellow-500',
    High: 'bg-orange-500',
    Critical: 'bg-red-600',
  };

  const emojis = {
    Low: '🟢',
    Medium: '🟡',
    High: '🟠',
    Critical: '🔴',
  };

  return (
    <span 
      className={`inline-flex items-center text-white px-3 py-1 rounded-full text-sm font-medium ${colors[level]} ${className}`}
    >
      {emojis[level]} {level.toUpperCase()}
    </span>
  );
}
