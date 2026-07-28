\set ON_ERROR_STOP on

\if :{?source_database}
\else
  \echo 'source_database is required'
  \quit 2
\endif

\if :{?destination_database}
\else
  \echo 'destination_database is required'
  \quit 2
\endif

SELECT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = :'source_database'
) AS source_exists
\gset

SELECT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = :'destination_database'
) AS destination_exists
\gset

\if :source_exists
\else
  \echo 'Source database does not exist'
  \quit 2
\endif

\if :destination_exists
  \echo 'Destination database already exists'
  \quit 2
\endif

SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
 WHERE datname = :'source_database'
   AND pid <> pg_backend_pid();

SELECT format(
    'ALTER DATABASE %I RENAME TO %I',
    :'source_database',
    :'destination_database'
)
\gexec
