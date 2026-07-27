-- PostgreSQL substring returns the first capture group when one is present.
-- Earlier migrations captured only the month name, causing the missing year
-- to be stored as a BC date. Capture the complete month-year value instead.
UPDATE finding_observations
SET report_period_date = to_date(
    substring(
        report_period
        FROM '((?:January|February|March|April|May|June|July|August|September|October|November|December)[[:space:]]+[0-9]{4})'
    ),
    'FMMonth YYYY'
)
WHERE (report_period_date IS NULL OR report_period_date < DATE '2000-01-01')
  AND report_period ~ '(January|February|March|April|May|June|July|August|September|October|November|December)[[:space:]]+[0-9]{4}';
