-- Moorings by month, with window functions. CC0-1.0, exav project.
CREATE TABLE vessel (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL UNIQUE,
    length_m  REAL NOT NULL CHECK (length_m > 0),
    kind      TEXT NOT NULL DEFAULT 'sloop'
);

CREATE TABLE stay (
    id        INTEGER PRIMARY KEY,
    vessel_id INTEGER NOT NULL REFERENCES vessel (id),
    berth     INTEGER NOT NULL,
    arrived   DATE NOT NULL,
    nights    INTEGER NOT NULL,
    fee_eur   NUMERIC(8, 2)
);

CREATE INDEX stay_by_arrival ON stay (arrived);

WITH monthly AS (
    SELECT strftime('%Y-%m', arrived) AS month,
           count(*)                    AS stays,
           sum(nights)                 AS nights,
           sum(fee_eur)                AS income
    FROM stay
    GROUP BY 1
)
SELECT month,
       stays,
       income,
       income - lag(income) OVER (ORDER BY month) AS change,
       round(100.0 * income / sum(income) OVER (), 1) AS share_pct,
       rank() OVER (ORDER BY income DESC) AS income_rank
FROM monthly
ORDER BY month;

-- The ten longest boats that stayed more than three nights.
SELECT v.name, v.length_m, s.nights
FROM vessel AS v
JOIN stay AS s ON s.vessel_id = v.id
WHERE s.nights > 3 AND v.kind IN ('ketch', 'trawler')
ORDER BY v.length_m DESC
LIMIT 10;
