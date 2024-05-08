# APK merger pipeline

We use [Celery](https://docs.celeryq.dev/en/stable/index.html) for parallelization. The pipeline uses Docker for containerization.

## Usage

- Create a new environment file by copying `.env.template` and specifying the following directories:
  - `APK_DIR`: directory in which the APKs reside
  - `APK_JSON_PATH`: location of the `.json` file containing the list of applications to analyze
  - `MERGED_APK_DIR`: directory to save the merged APKs in
  - `RESULT_DIR`: directory to save the results in
  - `LOGS_PATH`: directory to save the log files in
  - `CONCURRENCY`: number of Celery worker processes 

- Start the Celery worker and the Flower UI. The Flower UI can be used to monitor the task progress. It is exposed on port `5555`.
  ```sh
  $ docker-compose --env-file <env_file> up -d
  ```

- Add the analyzer tasks to the queue
  ```sh
  $ docker-compose --env-file <env_file> --profile init up -d
  ```

## Docker build

- Build the worker image
  ```sh
  $ docker build --platform linux/amd64 -t registry.gitlab.secpriv.tuwien.ac.at/secpriv/systemsec/webview-injection/merger-worker:1.0.0 .
  ```

- Push the worker image
  ```sh
  $ docker push registry.gitlab.secpriv.tuwien.ac.at/secpriv/systemsec/webview-injection/merger-worker:1.0.0
  ```