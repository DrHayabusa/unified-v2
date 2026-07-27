-- Earlier browser builds could serialize a JavaScript year as a PostgreSQL BC
-- date. Rebuild historical month keys from the retained human-readable label.
UPDATE finding_observations
SET report_period_date = to_date(
    substring(report_period from '(January|February|March|April|May|June|July|August|September|October|November|December)[[:space:]]+[0-9]{4}'),
    'FMMonth YYYY'
)
WHERE (report_period_date IS NULL OR report_period_date < DATE '2000-01-01')
  AND report_period ~ '(January|February|March|April|May|June|July|August|September|October|November|December)[[:space:]]+[0-9]{4}';
