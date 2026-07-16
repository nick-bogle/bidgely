import aiohttp
from pydantic import BaseModel


# https://www.bidgely.com/customers/
class UtilityBase(BaseModel):
    "Base Class for a Bidgely customer."

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        raise NotImplementedError

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        raise NotImplementedError

    @staticmethod
    def api_url() -> str:
        """Return the base URL of the utility's Bidgely API host."""
        raise NotImplementedError

    @staticmethod
    def usage_endpoint() -> str:
        """Return the dashboard endpoint serving usage chart reads.

        Deployments serving "usage-chart-details" return the same reads nested
        under payload.usageChartDataList, and reject the skip-itemization param.
        """
        return "usage-chart-data"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        account_id: str,
    ) -> tuple[str, str]:
        """Login to the utility website.

        Return the Opower access token or None

        :raises InvalidAuth: if login information is incorrect
        """
        raise NotImplementedError
