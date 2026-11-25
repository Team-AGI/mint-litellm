"""저장소·패키지 신청 미리보기: npm·PyPI 판본은 커밋 칸(40자리 16진수)이 아니라 판본 칸에 든다."""

from mint_litellm.console.templating import templates


def render(**f):
    return templates.env.get_template("_repo_intake.html").render(f=f)


def test_an_npm_package_version_goes_in_the_version_field_so_the_form_can_be_submitted():
    page = render(kind="npm", repo="npm · @upstash/context7-mcp", name="context7_mcp",
                  commit="4.8.0", command="npx -y @upstash/context7-mcp@4.8.0")
    assert "판본" in page and 'pattern="[0-9a-f]{40}"' not in page  # 브라우저가 제출을 막았다


def test_a_git_commit_still_uses_the_commit_field():
    page = render(repo="https://github.com/o/r", name="r", commit="a" * 40,
                  command="uvx --from git+https://github.com/o/r@" + "a" * 40 + " r")
    assert 'pattern="[0-9a-f]{40}"' in page
