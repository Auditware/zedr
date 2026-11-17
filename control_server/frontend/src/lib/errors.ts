export class ApiError extends Error {
  readonly status: number
  readonly column: number | null
  readonly retryAfter: number | null

  constructor(status: number, message: string, column: number | null = null, retryAfter: number | null = null) {
    super(message)
    this.status = status
    this.column = column
    this.retryAfter = retryAfter
  }
}
