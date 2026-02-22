import random


def randomize_threshold(base: int):
    """
    Add randomness to security thresholds
    """
    jitter = random.randint(-2, 2)
    return max(3, base + jitter)


def randomize_delay(base: int):
    """
    Randomize delays (seconds)
    """
    jitter = random.randint(-10, 10)
    return max(5, base + jitter)