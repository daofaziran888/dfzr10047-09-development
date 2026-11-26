import { request } from './client'
import type { ActionResult } from '@/data/types'

export type ShareEligibility = {
  请求渠道: string
  字段名称: string
  关联批次: string
  授权编号: string
  授权状态: string
  授权归属: string
  可引用: boolean
  归属说明: string
  在途申请: {
    申请类别: string
    关联批次?: string
    可用: boolean
    采用方式: string
    原因: string
    系数值?: string
    系数出处?: string
    归一编号?: string
    引用授权?: string
    规则来源?: string
    原始单位?: string
    目标单位?: string
    归一取值?: string
    回执编号?: string
    拒绝归属?: string
  }
  下一笔新申请: {
    申请类别: string
    可用: boolean
    采用方式: string
    原因: string
    系数值?: string
    系数出处?: string
    归一编号?: string
    引用授权?: string
    规则来源?: string
    原始单位?: string
    目标单位?: string
    拒绝归属?: string
  }
  可选方式: { 方式: string; 可用: boolean; 系数值?: string; 系数出处?: string; 原因?: string }[]
  自有规则: Record<string, string> | null
  可用授权: {
    授权编号: string
    渠道范围: string
    关联批次: string
    申请类别: string
    换算系数: string
    共享凭据?: string
    status: string
  }[]
}

export type CastResultEntry = {
  ok?: boolean
  status?: string
  重复提交?: boolean
  系数值?: string
  系数出处?: string
  归一编号?: string
  引用授权?: string
  归一取值?: number | null
  目标单位?: string
  拒绝归属?: string
  被拒值?: string
  回执?: Record<string, unknown>
}

export type ReceiptRow = {
  id: number
  status: string
  回执编号: string
  关联批次: string
  字段名称: string
  请求渠道: string
  申请类别: string
  规则来源: string
  引用授权: string
  归一编号: string
  换算系数: string
  原始单位: string
  目标单位: string
  原始取值: string
  归一取值: string
  系数出处: string
  确认标记: string
  提交时间: string
  确认时间: string
  撤回时间?: string
  拒绝归属?: string
  拒绝原因?: string
  被拒值?: string
}

export type ConflictRow = {
  id: number
  status: string
  冲突编号: string
  关联批次: string
  字段名称: string
  来源渠道: string
  授权编号: string
  共享系数: string
  自有系数: string
  共享出处: string
  自有出处: string
  在途取值: string
  已确认取值: string
  冲突说明: string
  裁决建议: string
}

async function parseJson<T>(response: Response, fallback: string): Promise<T> {
  if (!response.ok) throw new Error(fallback)
  return (await response.json()) as T
}

export async function fetchEligibility(params: {
  channel: string
  field: string
  batch: string
  grant_no?: string
  source_unit?: string
}): Promise<ShareEligibility> {
  const query = new URLSearchParams({
    channel: params.channel,
    field: params.field,
    batch: params.batch,
    grant_no: params.grant_no ?? '',
    source_unit: params.source_unit ?? '',
  }).toString()
  return parseJson<ShareEligibility>(
    await request(`/api/unit-share/eligibility?${query}`),
    '共享资格读取失败',
  )
}

export async function castValue(payload: {
  channel: string
  field: string
  raw_value: string
  source_unit: string
  batch: string
  grant_no?: string
  request_kind?: string
  credential?: string
  cast_no?: string
  preferred?: string
}): Promise<ActionResult & { entry?: CastResultEntry }> {
  return parseJson(
    await request('/api/unit-share/cast', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
    '取值转型提交失败',
  )
}

export async function submitOwnFactor(payload: {
  channel: string
  field: string
  source_unit: string
  target_unit: string
  multiplier: string
  batch: string
}): Promise<ActionResult & { entry?: Record<string, unknown> }> {
  return parseJson(
    await request('/api/unit-share/own-factor', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
    '自有系数提交失败',
  )
}

export async function fetchReceipts(params: {
  batch?: string
  field?: string
  channel?: string
} = {}): Promise<ReceiptRow[]> {
  const query = new URLSearchParams(params as Record<string, string>).toString()
  const payload = await parseJson<{ items: ReceiptRow[] }>(
    await request(`/api/unit-share/receipts?${query}`),
    '转型回执读取失败',
  )
  return payload.items
}

export async function fetchConflicts(batch = ''): Promise<ConflictRow[]> {
  const query = new URLSearchParams({ batch }).toString()
  const payload = await parseJson<{ items: ConflictRow[] }>(
    await request(`/api/unit-share/conflicts?${query}`),
    '来源规则冲突读取失败',
  )
  return payload.items
}

export async function resolveConflict(
  conflictNo: string,
  keep: string,
): Promise<ActionResult> {
  return parseJson(
    await request(`/api/unit-share/conflicts/${conflictNo}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ keep }),
    }),
    '冲突裁决失败',
  )
}

export async function withdrawInFlight(payload: {
  channel: string
  field: string
  batch: string
}): Promise<ActionResult> {
  return parseJson(
    await request('/api/unit-share/in-flight/withdraw', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
    '撤回在途申请失败',
  )
}

export type GrantPayload = {
  grant_no?: string
  field: string
  source_unit: string
  target_unit: string
  multiplier: string
  grantor_channel: string
  grantee_channel: string
  batch: string
  request_kind: string
  grantor_name?: string
  grantee_name?: string
  remark?: string
}

export async function grantShare(payload: GrantPayload): Promise<ActionResult> {
  return parseJson(
    await request('/api/unit-share/grants', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
    '共享授权签发失败',
  )
}

export async function revokeGrant(
  grantNo: string,
  reason = '',
): Promise<ActionResult> {
  return parseJson(
    await request(`/api/unit-share/grants/${grantNo}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
    '共享授权撤回失败',
  )
}

export async function fetchGrants(params: {
  channel?: string
  field?: string
} = {}): Promise<Record<string, string>[]> {
  const query = new URLSearchParams(params as Record<string, string>).toString()
  const payload = await parseJson<{ items: Record<string, string>[] }>(
    await request(`/api/unit-share/grants?${query}`),
    '共享授权读取失败',
  )
  return payload.items
}

export async function verifyCredential(
  credential: string,
): Promise<ActionResult> {
  return parseJson(
    await request('/api/unit-share/credentials/verify', {
      method: 'POST',
      body: JSON.stringify({ credential }),
    }),
    '共享凭据校验失败',
  )
}

export type ProvenanceResult = {
  ok: boolean
  message: string
  fields: Record<string, string>[]
  failures: string[]
  关联批次?: string
}

export async function fetchProvenance(batch: string, field = ''): Promise<ProvenanceResult> {
  const query = new URLSearchParams({ batch, field }).toString()
  return parseJson(
    await request(`/api/unit-share/provenance?${query}`),
    '系数出处读取失败',
  )
}

export async function checkContractProvenance(
  contractNo: string,
  batch = '',
): Promise<ProvenanceResult> {
  const query = new URLSearchParams({ contract_no: contractNo, batch }).toString()
  return parseJson(
    await request(`/api/unit-share/contract-check?${query}`),
    '输出契约系数出处复核失败',
  )
}
