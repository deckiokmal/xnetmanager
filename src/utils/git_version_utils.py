import git
import os


class GitUtils:
    def __init__(self, repo_path):
        """
        Initialize the Git repository at the specified path.
        If the repository doesn't exist, it will be initialized.
        """
        self.repo_path = repo_path
        if not os.path.exists(repo_path):
            os.makedirs(repo_path)
        if not os.path.exists(os.path.join(repo_path, ".git")):
            self.repo = git.Repo.init(repo_path)
        else:
            self.repo = git.Repo(repo_path)

    def commit_backup(self, file_path, commit_message):
        """
        Commit the specified file to the repository with the given commit message.
        """
        try:
            # Ensure the file is within the repository
            if not file_path.startswith(self.repo_path):
                raise ValueError("File path is outside of the repository")

            # Add and commit the file
            self.repo.index.add([file_path])
            commit = self.repo.index.commit(commit_message)
            return commit.hexsha
        except Exception as e:
            raise RuntimeError(f"Failed to commit backup: {e}")

    def rollback_to_commit(self, commit_hash):
        """
        Rollback the repository to the specified commit hash.
        """
        try:
            self.repo.git.reset("--hard", commit_hash)
            return True
        except Exception as e:
            raise RuntimeError(f"Failed to rollback to commit {commit_hash}: {e}")

    def get_diff_between_commits(self, old_commit_hash, new_commit_hash):
        """
        Get the diff between two commits identified by their hashes.
        """
        try:
            old_commit = self.repo.commit(old_commit_hash)
            new_commit = self.repo.commit(new_commit_hash)
            diff = old_commit.diff(new_commit)
            return diff
        except Exception as e:
            raise RuntimeError(
                f"Failed to get diff between commits {old_commit_hash} and {new_commit_hash}: {e}"
            )

    def get_commit_history(self, max_count=10):
        """
        Get the commit history of the repository.
        """
        try:
            commits = list(self.repo.iter_commits("master", max_count=max_count))
            return commits
        except Exception as e:
            raise RuntimeError(f"Failed to retrieve commit history: {e}")

    def get_file_at_commit(self, file_path, commit_hash):
        """
        Get the content of a file at a specific commit.
        """
        try:
            commit = self.repo.commit(commit_hash)
            blob = commit.tree / os.path.relpath(file_path, self.repo_path)
            return blob.data_stream.read().decode("utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to retrieve file at commit {commit_hash}: {e}")
