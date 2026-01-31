use incitape_core::{AppError, AppResult};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplaySpeed {
    numerator: u64,
    denominator: u64,
    zero: bool,
}

impl ReplaySpeed {
    pub fn parse(input: &str) -> AppResult<Self> {
        let value = input.trim();
        if value.is_empty() {
            return Err(AppError::usage("speed value is empty"));
        }
        if value == "0" || value == "0x" {
            return Ok(Self::zero());
        }
        let value = value
            .strip_suffix('x')
            .ok_or_else(|| AppError::usage("speed must be in the form <num>x or 0"))?;

        let mut parts = value.splitn(2, '.');
        let whole = parts.next().unwrap_or("");
        let frac = parts.next();
        if whole.is_empty() && frac.is_none() {
            return Err(AppError::usage("speed must be in the form <num>x or 0"));
        }

        let (numerator, denominator) = match frac {
            None => parse_fraction(whole, "")?,
            Some(frac) => parse_fraction(whole, frac)?,
        };

        if numerator == 0 {
            return Err(AppError::usage("speed must be greater than zero"));
        }

        Ok(Self {
            numerator,
            denominator,
            zero: false,
        })
    }

    pub fn zero() -> Self {
        Self {
            numerator: 0,
            denominator: 1,
            zero: true,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.zero
    }

    pub fn scale_delay(&self, delta_nanos: u64) -> Duration {
        if self.zero {
            return Duration::from_nanos(0);
        }
        let numerator = self.numerator as u128;
        let denominator = self.denominator as u128;
        let scaled = (delta_nanos as u128)
            .saturating_mul(denominator)
            .saturating_div(numerator);
        let nanos = scaled.min(u64::MAX as u128) as u64;
        Duration::from_nanos(nanos)
    }
}

fn parse_fraction(whole: &str, frac: &str) -> AppResult<(u64, u64)> {
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::usage("speed must be numeric"));
    }
    let mut digits = String::new();
    digits.push_str(if whole.is_empty() { "0" } else { whole });
    let denominator = if frac.is_empty() {
        1u64
    } else {
        digits.push_str(frac);
        let power = frac.len() as u32;
        10u64
            .checked_pow(power)
            .ok_or_else(|| AppError::usage("speed precision too large"))?
    };
    let numerator = digits
        .parse::<u128>()
        .map_err(|_| AppError::usage("speed out of range"))?;
    if numerator > u64::MAX as u128 {
        return Err(AppError::usage("speed out of range"));
    }
    Ok((numerator as u64, denominator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_speed_values() {
        let speed = ReplaySpeed::parse("1x").unwrap();
        assert!(!speed.is_zero());
        let speed = ReplaySpeed::parse("0").unwrap();
        assert!(speed.is_zero());
        let speed = ReplaySpeed::parse("2.5x").unwrap();
        assert_eq!(
            speed.scale_delay(10_000_000),
            Duration::from_nanos(4_000_000)
        );
    }

    #[test]
    fn rejects_invalid_speed() {
        assert!(ReplaySpeed::parse("fast").is_err());
        assert!(ReplaySpeed::parse("0.0x").is_err());
        assert!(ReplaySpeed::parse("1").is_err());
    }
}
