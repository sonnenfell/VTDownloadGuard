using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace VTDownloadGuard.Services;

public sealed record RateLimiterSnapshot(
    int RequestsInWindow,
    int MaxRequestsPerWindow,
    double WindowSeconds,
    TimeSpan NextSlotIn,
    TimeSpan CooldownRemaining);

/// <summary>
/// Sliding-window async rate limiter with zero busy-polling.
/// Serializes slot acquisition cleanly across concurrent callers.
/// </summary>
public sealed class RateLimiter
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Queue<DateTimeOffset> _timestamps = new();
    private readonly TimeSpan _window;
    private readonly Func<DateTimeOffset> _utcNow;

    private int _maxRequestsPerWindow;
    private DateTimeOffset _cooldownUntil = DateTimeOffset.MinValue;

    public RateLimiter(int maxRequestsPerMinute = 4, TimeSpan? window = null, Func<DateTimeOffset>? utcNow = null)
    {
        _maxRequestsPerWindow = Math.Max(1, maxRequestsPerMinute);
        _window = window ?? TimeSpan.FromSeconds(61);
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public void UpdateLimit(int maxRequestsPerMinute)
    {
        Volatile.Write(ref _maxRequestsPerWindow, Math.Max(1, maxRequestsPerMinute));
    }

    public void NotifyRateLimitHit(TimeSpan cooldown)
    {
        var until = _utcNow() + cooldown;
        lock (_timestamps)
        {
            if (until > _cooldownUntil)
            {
                _cooldownUntil = until;
            }
        }
    }

    public RateLimiterSnapshot GetSnapshot()
    {
        DateTimeOffset now = _utcNow();
        int limit = Volatile.Read(ref _maxRequestsPerWindow);

        lock (_timestamps)
        {
            while (_timestamps.Count > 0 && (now - _timestamps.Peek()) >= _window)
            {
                _timestamps.Dequeue();
            }

            TimeSpan cooldown = _cooldownUntil > now ? _cooldownUntil - now : TimeSpan.Zero;
            TimeSpan nextSlot = TimeSpan.Zero;

            if (_timestamps.Count >= limit && _timestamps.Count > 0)
            {
                nextSlot = (_timestamps.Peek() + _window) - now;
                if (nextSlot < TimeSpan.Zero)
                {
                    nextSlot = TimeSpan.Zero;
                }
            }

            if (cooldown > nextSlot)
            {
                nextSlot = cooldown;
            }

            return new RateLimiterSnapshot(
                _timestamps.Count,
                limit,
                _window.TotalSeconds,
                nextSlot,
                cooldown);
        }
    }

    public async Task WaitForSlotAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                DateTimeOffset now = _utcNow();
                TimeSpan waitTime = TimeSpan.Zero;

                lock (_timestamps)
                {
                    if (_cooldownUntil > now)
                    {
                        waitTime = _cooldownUntil - now;
                    }
                    else
                    {
                        while (_timestamps.Count > 0 && (now - _timestamps.Peek()) >= _window)
                        {
                            _timestamps.Dequeue();
                        }

                        int limit = Volatile.Read(ref _maxRequestsPerWindow);
                        if (_timestamps.Count < limit)
                        {
                            _timestamps.Enqueue(now);
                            return;
                        }

                        DateTimeOffset oldest = _timestamps.Peek();
                        waitTime = (oldest + _window) - now;
                        if (waitTime < TimeSpan.FromMilliseconds(10))
                        {
                            waitTime = TimeSpan.FromMilliseconds(10);
                        }
                    }
                }

                await Task.Delay(waitTime, ct).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }
}
