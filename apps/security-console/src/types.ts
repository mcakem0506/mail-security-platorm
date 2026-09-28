export const RISK_LABELS: Record<string, string> = {
  LOW_RISK: "Низкий риск",
  SUSPICIOUS: "Подозрительно",
  HIGH_RISK: "Высокий риск",
  MALICIOUS: "Вредоносное",
  UNKNOWN: "Неизвестно",
};

export const SEVERITY_LABELS: Record<string, string> = {
  info: "Информация",
  low: "Низкая",
  medium: "Средняя",
  high: "Высокая",
  critical: "Критическая",
};

export const INCIDENT_STATUS_LABELS: Record<string, string> = {
  NEW: "Новый",
  TRIAGE: "Триаж",
  INVESTIGATING: "Расследование",
  CONFIRMED_PHISHING: "Подтверждён фишинг",
  CONFIRMED_MALWARE: "Подтверждено ВПО",
  CONFIRMED_BEC: "Подтверждён BEC",
  FALSE_POSITIVE: "Ложное срабатывание",
  BENIGN: "Безвредно",
  REMEDIATION_PENDING: "Ожидает реагирования",
  REMEDIATED: "Реагирование выполнено",
  CLOSED: "Закрыт",
};

export const REMEDIATION_STATE_LABELS: Record<string, string> = {
  PROPOSED: "Предложено",
  APPROVED: "Согласовано",
  REJECTED: "Отклонено",
  EXECUTED: "Выполнено",
  DRY_RUN_EXECUTED: "Выполнен dry-run",
  FAILED: "Ошибка",
  CANCELLED: "Отменено",
};

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString("ru-RU");
  } catch {
    return value;
  }
}
