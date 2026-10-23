// Concurrency slots with a FIFO wait queue. Queue wait is what tells us the client is saturated.

export class Pool {
  private inUse = 0;
  private waiters: Array<() => void> = [];
  maxQueueSeen = 0;

  constructor(readonly name: string, readonly capacity: number) {
    if (capacity < 1) throw new Error(`pool ${name}: capacity must be >= 1`);
  }

  get busy(): number { return this.inUse; }
  get queued(): number { return this.waiters.length; }

  // Resolves with a release function once a slot is free.
  async acquire(): Promise<() => void> {
    if (this.inUse < this.capacity) {
      this.inUse++;
      return this.releaser();
    }
    await new Promise<void>((res) => {
      this.waiters.push(res);
      if (this.waiters.length > this.maxQueueSeen) this.maxQueueSeen = this.waiters.length;
    });
    this.inUse++;
    return this.releaser();
  }

  private releaser(): () => void {
    let done = false;
    return () => {
      if (done) return;
      done = true;
      this.inUse--;
      const next = this.waiters.shift();
      if (next) next();
    };
  }
}
