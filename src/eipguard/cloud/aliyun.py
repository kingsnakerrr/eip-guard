from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass
from typing import Any

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkcore.acs_exception.exceptions import ClientException, ServerException

log = logging.getLogger(__name__)

RETRYABLE_CODES = {
    "Throttling",
    "Throttling.User",
    "Throttling.Api",
    "ServiceUnavailable",
    "InternalError",
    "UnknownError",
    "OperationConflict",
}


class AliyunError(RuntimeError):
    def __init__(self, action: str, code: str, message: str, request_id: str = "") -> None:
        self.action = action
        self.code = code
        self.request_id = request_id
        super().__init__(f"{action} 失败 [{code}] {message}" + (f" (requestId={request_id})" if request_id else ""))


@dataclass
class EipInfo:
    allocation_id: str
    ip: str
    status: str = ""
    instance_id: str = ""
    instance_type: str = ""
    bandwidth: str = ""
    charge_type: str = ""
    isp: str = ""

    @property
    def bound(self) -> bool:
        return self.status.lower() == "inuse" or bool(self.instance_id)

    def describe(self) -> str:
        tail = f" → {self.instance_id}" if self.instance_id else " (未绑定)"
        return f"{self.ip} [{self.status or '?'}]{tail}"


class AliyunVpc:
    """阿里云 VPC/EIP 的异步薄封装（SDK 是同步的，放到线程里跑）。"""

    def __init__(
        self,
        access_key_id: str,
        access_key_secret: str,
        region_id: str = "cn-hongkong",
        endpoint: str = "vpc.aliyuncs.com",
        api_version: str = "2016-04-28",
    ) -> None:
        self.region_id = region_id
        self.endpoint = endpoint
        self.api_version = api_version
        self._client = AcsClient(access_key_id, access_key_secret, region_id)
        self._client.set_stream_logger = None  # 避免 SDK 自己打日志

    # ---------------- 底层调用 ----------------
    def _build(self, action: str, params: dict[str, Any]) -> CommonRequest:
        req = CommonRequest()
        req.set_method("POST")
        req.set_protocol_type("https")
        req.set_domain(self.endpoint)
        req.set_version(self.api_version)
        req.set_action_name(action)
        req.set_accept_format("json")
        for key, value in params.items():
            if value is None or value == "":
                continue
            req.add_query_param(key, value)
        return req

    def _call_sync(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        req = self._build(action, params)
        try:
            raw = self._client.do_action_with_exception(req)
        except ServerException as exc:
            raise AliyunError(
                action,
                exc.get_error_code() or "ServerError",
                exc.get_error_msg() or str(exc),
                exc.get_request_id() or "",
            ) from exc
        except ClientException as exc:
            raise AliyunError(action, "ClientError", str(exc)) from exc
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        data = json.loads(raw) if raw else {}
        if not isinstance(data, dict):
            raise AliyunError(action, "BadResponse", f"响应格式异常: {data!r}")
        return data

    async def call(
        self,
        action: str,
        params: dict[str, Any],
        *,
        retries: int = 3,
        region_id: str | None = None,
    ) -> dict[str, Any]:
        payload = dict(params)
        payload.setdefault("RegionId", region_id or self.region_id)
        last: AliyunError | None = None
        for attempt in range(1, retries + 1):
            started = time.monotonic()
            try:
                data = await asyncio.to_thread(self._call_sync, action, payload)
                log.debug("aliyun %s ok in %.0fms", action, (time.monotonic() - started) * 1000)
                return data
            except AliyunError as exc:
                last = exc
                if exc.code not in RETRYABLE_CODES or attempt >= retries:
                    raise
                delay = min(8.0, 0.8 * 2 ** (attempt - 1)) + random.uniform(0, 0.5)
                log.warning("%s 可重试错误 %s，%.1fs 后重试 (%d/%d)", action, exc.code, delay, attempt, retries)
                await asyncio.sleep(delay)
        assert last is not None
        raise last

    # ---------------- EIP ----------------
    async def describe_eips(
        self,
        *,
        allocation_id: str | None = None,
        instance_id: str | None = None,
        ip: str | None = None,
        status: str | None = None,
        region_id: str | None = None,
    ) -> list[EipInfo]:
        out: list[EipInfo] = []
        page = 1
        while True:
            params: dict[str, Any] = {"PageSize": 100, "PageNumber": page}
            if allocation_id:
                params["AllocationId"] = allocation_id
            if instance_id:
                params["AssociatedInstanceId"] = instance_id
                params["AssociatedInstanceType"] = "EcsInstance"
            if ip:
                params["EipAddress"] = ip
            if status:
                params["Status"] = status
            data = await self.call("DescribeEipAddresses", params, region_id=region_id)
            items = (data.get("EipAddresses") or {}).get("EipAddress") or []
            for item in items:
                out.append(
                    EipInfo(
                        allocation_id=str(item.get("AllocationId") or ""),
                        ip=str(item.get("IpAddress") or item.get("EipAddress") or ""),
                        status=str(item.get("Status") or ""),
                        instance_id=str(item.get("InstanceId") or ""),
                        instance_type=str(item.get("InstanceType") or ""),
                        bandwidth=str(item.get("Bandwidth") or ""),
                        charge_type=str(item.get("InternetChargeType") or ""),
                        isp=str(item.get("ISP") or ""),
                    )
                )
            total = int(data.get("TotalCount") or 0)
            if page * 100 >= total or not items:
                break
            page += 1
        return out

    async def get_eip(self, allocation_id: str, region_id: str | None = None) -> EipInfo | None:
        items = await self.describe_eips(allocation_id=allocation_id, region_id=region_id)
        for item in items:
            if item.allocation_id == allocation_id:
                return item
        return items[0] if items else None

    async def find_instance_eip(self, instance_id: str, region_id: str | None = None) -> EipInfo | None:
        items = await self.describe_eips(instance_id=instance_id, region_id=region_id)
        for item in items:
            if item.instance_id == instance_id:
                return item
        return items[0] if items else None

    async def allocate_eip(
        self,
        *,
        internet_charge_type: str = "",
        bandwidth_mbps: int | None = None,
        isp: str = "",
        region_id: str | None = None,
    ) -> EipInfo:
        params: dict[str, Any] = {"Quantity": 1}
        if internet_charge_type:
            params["InternetChargeType"] = internet_charge_type
        # PayByTraffic 不接受 Bandwidth；只有按带宽计费时才传
        if bandwidth_mbps and internet_charge_type.lower() != "paybytraffic":
            params["Bandwidth"] = int(bandwidth_mbps)
        if isp:
            params["ISP"] = isp
        data = await self.call("AllocateEipAddress", params, region_id=region_id)
        allocation_id = str(data.get("AllocationId") or "")
        ip = str(data.get("EipAddress") or "")
        if not allocation_id:
            raise AliyunError("AllocateEipAddress", "NoAllocationId", f"响应缺少 AllocationId: {data}")
        log.info("已分配新 EIP %s (%s)", ip, allocation_id)
        return EipInfo(allocation_id=allocation_id, ip=ip, status="Available")

    async def associate(self, allocation_id: str, instance_id: str, region_id: str | None = None) -> None:
        await self.call(
            "AssociateEipAddress",
            {"AllocationId": allocation_id, "InstanceId": instance_id, "InstanceType": "EcsInstance"},
            region_id=region_id,
        )

    async def unassociate(
        self, allocation_id: str, instance_id: str = "", region_id: str | None = None
    ) -> None:
        params: dict[str, Any] = {"AllocationId": allocation_id}
        if instance_id:
            params["InstanceId"] = instance_id
            params["InstanceType"] = "EcsInstance"
        await self.call("UnassociateEipAddress", params, region_id=region_id)

    async def release(self, allocation_id: str, region_id: str | None = None) -> None:
        await self.call("ReleaseEipAddress", {"AllocationId": allocation_id}, region_id=region_id)
        log.info("已释放 EIP %s", allocation_id)

    async def wait_status(
        self,
        allocation_id: str,
        wanted: set[str],
        *,
        timeout: float = 90.0,
        interval: float = 2.0,
        region_id: str | None = None,
    ) -> EipInfo:
        wanted_lower = {w.lower() for w in wanted}
        deadline = time.monotonic() + timeout
        last: EipInfo | None = None
        while time.monotonic() < deadline:
            info = await self.get_eip(allocation_id, region_id=region_id)
            if info:
                last = info
                if info.status.lower() in wanted_lower:
                    return info
            await asyncio.sleep(interval)
        status = last.describe() if last else "查不到"
        raise AliyunError(
            "DescribeEipAddresses",
            "WaitTimeout",
            f"EIP {allocation_id} 等待状态 {sorted(wanted)} 超时，当前 {status}",
        )
