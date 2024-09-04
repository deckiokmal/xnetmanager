import git
import os
import logging


class GitUtils:
    def __init__(self, repo_path):
        """
        Initialize the Git repository at the specified path.
        If the repository doesn't exist, it will be initialized.
        """
        self.repo_path = os.path.abspath(repo_path)  # Securely handle paths
        if not os.path.exists(self.repo_path):
            os.makedirs(self.repo_path)
        if not os.path.exists(os.path.join(self.repo_path, ".git")):
            self.repo = git.Repo.init(self.repo_path)
            logging.info(f"Initialized a new Git repository at {self.repo_path}")
        else:
            self.repo = git.Repo(self.repo_path)
            logging.info(f"Using existing Git repository at {self.repo_path}")

    def commit_backup(self, file_path, commit_message):
        """
        Commit the specified file to the repository with the given commit message.
        """
        try:
            abs_file_path = os.path.abspath(file_path)
            if not abs_file_path.startswith(self.repo_path):
                raise ValueError("File path is outside of the repository")

            self.repo.index.add([abs_file_path])
            commit = self.repo.index.commit(commit_message)
            logging.info(f"Committed {abs_file_path} with message: '{commit_message}'")
            return commit.hexsha
        except git.exc.GitCommandError as e:
            logging.error(f"Git command error during commit: {e}")
            raise RuntimeError(f"Failed to commit backup: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during commit: {e}")
            raise RuntimeError(f"Failed to commit backup: {e}")

    def rollback_to_commit(self, commit_hash):
        """
        Rollback the repository to the specified commit hash.
        """
        try:
            self.repo.git.reset("--hard", commit_hash)
            logging.info(f"Repository rolled back to commit {commit_hash}")
            return True
        except git.exc.GitCommandError as e:
            logging.error(f"Git command error during rollback: {e}")
            raise RuntimeError(f"Failed to rollback to commit {commit_hash}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during rollback: {e}")
            raise RuntimeError(f"Failed to rollback to commit {commit_hash}: {e}")

    def get_diff_between_commits(self, old_commit_hash, new_commit_hash):
        """
        Get the diff between two commits identified by their hashes.
        """
        try:
            old_commit = self.repo.commit(old_commit_hash)
            new_commit = self.repo.commit(new_commit_hash)
            diff = old_commit.diff(new_commit)
            logging.info(
                f"Generated diff between commits {old_commit_hash} and {new_commit_hash}"
            )
            return diff
        except git.exc.BadName as e:
            logging.error(f"Invalid commit hash: {e}")
            raise RuntimeError(f"Invalid commit hash: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during diff generation: {e}")
            raise RuntimeError(
                f"Failed to get diff between commits {old_commit_hash} and {new_commit_hash}: {e}"
            )

    def get_commit_history(self, max_count=10):
        """
        Get the commit history of the repository.
        """
        try:
            commits = list(self.repo.iter_commits("master", max_count=max_count))
            logging.info(f"Retrieved commit history, count: {len(commits)}")
            return commits
        except git.exc.GitCommandError as e:
            logging.error(f"Git command error during commit history retrieval: {e}")
            raise RuntimeError(f"Failed to retrieve commit history: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during commit history retrieval: {e}")
            raise RuntimeError(f"Failed to retrieve commit history: {e}")

    def get_file_at_commit(self, file_path, commit_hash):
        """
        Get the content of a file at a specific commit.
        """
        try:
            abs_file_path = os.path.abspath(file_path)
            commit = self.repo.commit(commit_hash)
            blob = commit.tree / os.path.relpath(abs_file_path, self.repo_path)
            file_content = blob.data_stream.read().decode("utf-8")
            logging.info(f"Retrieved file {abs_file_path} at commit {commit_hash}")
            return file_content
        except git.exc.BadName as e:
            logging.error(f"Invalid commit hash: {e}")
            raise RuntimeError(f"Invalid commit hash: {e}")
        except KeyError:
            logging.error(f"File {abs_file_path} not found at commit {commit_hash}")
            raise FileNotFoundError(
                f"File {abs_file_path} not found at commit {commit_hash}"
            )
        except Exception as e:
            logging.error(f"Unexpected error during file retrieval: {e}")
            raise RuntimeError(f"Failed to retrieve file at commit {commit_hash}: {e}")
