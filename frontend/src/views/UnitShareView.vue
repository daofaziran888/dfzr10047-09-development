<template>
  <section class="page" data-module="unit_share">
    <header class="page-head">
      <div>
        <h2>系数共享授权</h2>
        <p class="page-desc">
          来源负责人按渠道范围授权或撤回换算系数；凭据由服务端签发，在途申请与下一笔新申请分别核对资格。
        </p>
      </div>
      <div class="page-actions">
        <button class="btn primary" data-testid="open-grant" type="button" @click="showForm = true">
          授权共享系数
        </button>
        <RouterLink class="btn" data-testid="to-cast" to="/unit_share/cast">进入转型核对</RouterLink>
      </div>
    </header>

    <p v-if="errorMessage" class="error-text" data-testid="share-error">{{ errorMessage }}</p>
    <p v-if="notice" class="notice-text" data-testid="share-notice">{{ notice }}</p>

    <section class="panel">
      <h3>授权清单</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>授权编号</th><th>字段</th><th>换算</th><th>渠道范围</th>
            <th>关联批次</th><th>申请类别</th><th>状态</th><th>签发/撤回</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="grant in grants" :key="grant.授权编号" :data-testid="`grant-${grant.授权编号}`">
            <td>{{ grant.授权编号 }}</td>
            <td>{{ grant.字段名称 }}</td>
            <td>{{ grant.原始单位 }}→{{ grant.目标单位 }} ×{{ grant.换算系数 }}</td>
            <td>{{ grant.授予方渠道 }}→{{ grant.受让方渠道 }}</td>
            <td>{{ grant.关联批次 }}</td>
            <td>{{ grant.申请类别 }}</td>
            <td>{{ grant.status }}</td>
            <td>
              <div>签发 {{ grant.签发时间 || '—' }}</div>
              <div v-if="grant.撤回时间">撤回 {{ grant.撤回时间 }}</div>
            </td>
            <td class="row-actions">
              <button
                v-if="grant.status === '已授权'"
                class="link"
                type="button"
                :data-testid="`revoke-${grant.授权编号}`"
                @click="onRevoke(grant.授权编号)"
              >
                撤回
              </button>
              <span v-else>—</span>
            </td>
          </tr>
          <tr v-if="!grants.length">
            <td colspan="9" class="empty-state">暂无共享授权</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h3>资格核对 · 在途申请与下一笔新申请</h3>
      <form class="filter-bar" @submit.prevent="checkEligibility">
        <label class="filter-item">
          <span>受让方渠道</span>
          <input v-model="probe.channel" data-testid="probe-channel" />
        </label>
        <label class="filter-item">
          <span>字段名称</span>
          <input v-model="probe.field" data-testid="probe-field" />
        </label>
        <label class="filter-item">
          <span>关联批次</span>
          <input v-model="probe.batch" data-testid="probe-batch" />
        </label>
        <button class="btn" data-testid="probe-submit" type="submit">核对资格</button>
      </form>
      <div v-if="probeResult" class="analysis-summary" data-testid="probe-result">
        <article class="analysis-card">
          <h3>在途申请</h3>
          <p><strong data-testid="probe-in-flight">{{ probeResult.在途申请.采用方式 }}</strong></p>
          <p>系数：{{ probeResult.在途申请.系数值 ?? '—' }} {{ probeResult.在途申请.原始单位 ?? '' }}</p>
          <p>出处：{{ probeResult.在途申请.系数出处 ?? '—' }}</p>
          <p>{{ probeResult.在途申请.原因 }}</p>
        </article>
        <article class="analysis-card">
          <h3>下一笔新申请</h3>
          <p><strong data-testid="probe-next">{{ probeResult.下一笔新申请.采用方式 }}</strong></p>
          <p>系数：{{ probeResult.下一笔新申请.系数值 ?? '—' }} {{ probeResult.下一笔新申请.原始单位 ?? '' }}</p>
          <p>出处：{{ probeResult.下一笔新申请.系数出处 ?? '—' }}</p>
          <p>{{ probeResult.下一笔新申请.原因 }}</p>
        </article>
        <article class="analysis-card">
          <h3>授权归属</h3>
          <p>{{ probeResult.授权归属 || '无可引用授权' }}</p>
          <p>可否引用：{{ probeResult.可引用 ? '可引用' : '不可引用' }}</p>
          <p v-if="probeResult.归属说明">{{ probeResult.归属说明 }}</p>
        </article>
      </div>
    </section>

    <section class="panel">
      <h3>凭据校验</h3>
      <form class="filter-bar" @submit.prevent="onVerify">
        <label class="filter-item">
          <span>共享凭据令牌</span>
          <input v-model="verifyToken" data-testid="verify-token" placeholder="ugs1.…" />
        </label>
        <button class="btn" data-testid="verify-submit" type="submit">校验凭据</button>
      </form>
      <p v-if="verifyMessage" data-testid="verify-result">{{ verifyMessage }}</p>
    </section>

    <div v-if="showForm" class="modal-backdrop" data-testid="grant-modal">
      <form class="modal" @submit.prevent="submitGrant">
        <h3>授权共享系数</h3>
        <label v-for="field in grantFields" :key="field.key" class="create-field">
          <span>{{ field.label }}</span>
          <select
            v-if="field.options"
            v-model="grantValues[field.key as keyof GrantPayload]"
            :data-testid="`grant-${field.key}`"
          >
            <option v-for="option in field.options" :key="option" :value="option">{{ option }}</option>
          </select>
          <input
            v-else
            v-model="grantValues[field.key as keyof GrantPayload]"
            :data-testid="`grant-${field.key}`"
            :required="field.required"
          />
        </label>
        <p class="hint">
          关联批次填 * 表示该渠道范围内全部批次；留空或指定批次号则只覆盖授权批次，
          未授权的新批次不得采用跨渠道来源系数。
        </p>
        <div class="page-actions">
          <button class="btn" type="button" @click="showForm = false">取消</button>
          <button class="btn primary" data-testid="grant-submit" type="submit" :disabled="submitting">
            {{ submitting ? '签发中…' : '确认授权并签发凭据' }}
          </button>
        </div>
      </form>
    </div>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'

import {
  type GrantPayload,
  type ShareEligibility,
  fetchEligibility,
  fetchGrants,
  grantShare,
  revokeGrant,
  verifyCredential,
} from '@/api/unit-share'

type GrantRow = Record<string, string>

const grants = ref<GrantRow[]>([])
const errorMessage = ref('')
const notice = ref('')
const showForm = ref(false)
const submitting = ref(false)
const verifyToken = ref('')
const verifyMessage = ref('')
const probe = ref({ channel: 'web-upload', field: 'net_weight', batch: 'FI-20260905001' })
const probeResult = ref<ShareEligibility | null>(null)

const grantValues = ref<GrantPayload>({
  field: 'net_weight',
  source_unit: 'kg',
  target_unit: 'g',
  multiplier: '1000',
  grantor_channel: 'sftp-node-03',
  grantee_channel: 'web-upload',
  batch: 'FI-20260905001',
  request_kind: '在途批次',
  grantor_name: '来源负责人-甲',
  grantee_name: '渠道负责人-乙',
  remark: '',
})

type GrantField = {
  key: string
  label: string
  required: boolean
  options?: string[]
}

const grantFields: GrantField[] = [
  { key: 'field', label: '字段名称', required: true },
  { key: 'source_unit', label: '原始单位', required: true },
  { key: 'target_unit', label: '目标单位', required: true },
  { key: 'multiplier', label: '换算系数', required: true },
  { key: 'grantor_channel', label: '授予方渠道（来源负责人）', required: true },
  { key: 'grantee_channel', label: '受让方渠道', required: true },
  { key: 'batch', label: '关联批次（* 表示全部）', required: true },
  { key: 'request_kind', label: '申请类别', required: true, options: ['在途批次', '新批次'] },
  { key: 'grantor_name', label: '授予人', required: false },
  { key: 'grantee_name', label: '受让人', required: false },
  { key: 'remark', label: '授权依据', required: false },
]

async function reload() {
  errorMessage.value = ''
  try {
    grants.value = await fetchGrants()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '共享授权读取失败'
  }
}

async function submitGrant() {
  submitting.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    const result = await grantShare(grantValues.value)
    if (!result.ok) throw new Error(result.message)
    notice.value = result.message
    showForm.value = false
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '共享授权签发失败'
  } finally {
    submitting.value = false
  }
}

async function onRevoke(grantNo: string) {
  errorMessage.value = ''
  notice.value = ''
  try {
    const result = await revokeGrant(grantNo, '来源负责人撤回授权')
    if (!result.ok) throw new Error(result.message)
    notice.value = result.message
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '撤回失败'
  }
}

async function checkEligibility() {
  errorMessage.value = ''
  try {
    probeResult.value = await fetchEligibility({
      channel: probe.value.channel,
      field: probe.value.field,
      batch: probe.value.batch,
    })
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '资格核对失败'
  }
}

async function onVerify() {
  verifyMessage.value = ''
  try {
    const result = await verifyCredential(verifyToken.value)
    verifyMessage.value = `${result.ok ? '通过' : '拒绝'}：${result.message}`
  } catch (error) {
    verifyMessage.value = error instanceof Error ? error.message : '凭据校验失败'
  }
}

onMounted(reload)
</script>
