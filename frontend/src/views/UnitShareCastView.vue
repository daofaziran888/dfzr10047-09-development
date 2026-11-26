<template>
  <section class="page" data-module="unit_share_cast">
    <header class="page-head">
      <div>
        <h2>取值转型 · 单位换算核对</h2>
        <p class="page-desc">
          转型后的数值按服务端资格换算成归一字段值；在途申请与下一笔新申请分开核对，已确认字段保留当次系数。
        </p>
      </div>
      <div class="page-actions">
        <RouterLink class="btn" data-testid="to-grants" to="/unit_share">返回授权页</RouterLink>
        <button class="btn" data-testid="refresh" type="button" @click="refresh">重新核对资格</button>
      </div>
    </header>

    <form class="analysis-form" @submit.prevent="refresh">
      <label>
        <span>请求渠道</span>
        <select v-model="form.channel" data-testid="cast-channel">
          <option v-for="channel in channels" :key="channel" :value="channel">{{ channel }}</option>
        </select>
      </label>
      <label>
        <span>字段名称</span>
        <input v-model="form.field" data-testid="cast-field" />
      </label>
      <label>
        <span>关联批次</span>
        <input v-model="form.batch" data-testid="cast-batch" />
      </label>
      <label>
        <span>原始单位</span>
        <input v-model="form.source_unit" data-testid="cast-source-unit" />
      </label>
      <label>
        <span>转型后数值</span>
        <input v-model="form.raw_value" data-testid="cast-raw-value" />
      </label>
      <label>
        <span>引用授权编号（可空）</span>
        <input v-model="form.grant_no" data-testid="cast-grant-no" />
      </label>
      <button class="btn" data-testid="check-eligibility" type="submit">核对资格</button>
    </form>

    <p v-if="errorMessage" class="error-text" data-testid="cast-error">{{ errorMessage }}</p>
    <p v-if="notice" class="notice-text" data-testid="cast-notice">{{ notice }}</p>

    <section v-if="eligibility" class="analysis-summary" data-testid="eligibility">
      <article class="analysis-card" data-testid="in-flight-card">
        <h3>在途申请</h3>
        <p><strong>{{ eligibility.在途申请.采用方式 }}</strong></p>
        <dl class="dag-detail">
          <dt>可用</dt><dd>{{ eligibility.在途申请.可用 ? '是' : '否' }}</dd>
          <dt>采用系数</dt><dd data-testid="in-flight-factor">{{ eligibility.在途申请.系数值 ?? '—' }}</dd>
          <dt>系数出处</dt><dd data-testid="in-flight-source">{{ eligibility.在途申请.系数出处 ?? '—' }}</dd>
          <dt>归一取值</dt><dd>{{ eligibility.在途申请.归一取值 ?? '—' }}</dd>
          <dt>原因</dt><dd>{{ eligibility.在途申请.原因 }}</dd>
          <dt v-if="eligibility.在途申请.拒绝归属">拒绝归属</dt>
          <dd v-if="eligibility.在途申请.拒绝归属" data-testid="in-flight-owner">
            {{ eligibility.在途申请.拒绝归属 }}
          </dd>
        </dl>
      </article>
      <article class="analysis-card" data-testid="next-card">
        <h3>下一笔新申请</h3>
        <p><strong>{{ eligibility.下一笔新申请.采用方式 }}</strong></p>
        <dl class="dag-detail">
          <dt>可用</dt><dd>{{ eligibility.下一笔新申请.可用 ? '是' : '否' }}</dd>
          <dt>采用系数</dt><dd data-testid="next-factor">{{ eligibility.下一笔新申请.系数值 ?? '—' }}</dd>
          <dt>系数出处</dt><dd data-testid="next-source">{{ eligibility.下一笔新申请.系数出处 ?? '—' }}</dd>
          <dt>原因</dt><dd>{{ eligibility.下一笔新申请.原因 }}</dd>
        </dl>
      </article>
      <article class="analysis-card">
        <h3>授权归属</h3>
        <p data-testid="grant-owner">{{ eligibility.授权归属 || '无可引用授权' }}</p>
        <p data-testid="grant-quotable">可否引用：{{ eligibility.可引用 ? '可引用' : '不可引用' }}</p>
        <p v-if="eligibility.归属说明" data-testid="grant-owner-note">{{ eligibility.归属说明 }}</p>
        <p>授权状态：{{ eligibility.授权状态 || '—' }}</p>
        <p>授权编号：{{ eligibility.授权编号 || '—' }}</p>
        <p>自有规则：{{ eligibility.自有规则 ? eligibility.自有规则.系数出处 : '未登记' }}</p>
      </article>
    </section>

    <div class="page-actions">
      <label v-if="eligibility" class="filter-item">
        <span>换算方式</span>
        <select v-model="preferred" data-testid="cast-preferred">
          <option value="">按服务端默认（原请求优先）</option>
          <option
            v-for="option in eligibility.可选方式"
            :key="option.方式"
            :value="option.方式"
          >
            {{ option.方式 }}{{ option.可用 ? '' : '（不可用）' }}
          </option>
        </select>
      </label>
      <button class="btn primary" data-testid="cast-submit" type="button" @click="submitCast">
        按在途资格提交换算
      </button>
      <button class="btn" data-testid="withdraw-in-flight" type="button" @click="withdraw">
        撤回在途申请
      </button>
    </div>

    <section v-if="castResult" class="panel" data-testid="cast-result">
      <h3>{{ castResult.系数出处 ? '归一结果' : '提交被拒' }}</h3>
      <p><strong>{{ castResult.message }}</strong></p>
      <p data-testid="result-source">系数出处：{{ castResult.系数出处 || '—' }}</p>
      <p>归一编号：{{ castResult.归一编号 || '—' }} · 换算系数：{{ castResult.系数值 || '—' }}</p>
      <p>归一取值：{{ castResult.归一取值 ?? '—' }}</p>
      <p v-if="castResult.拒绝归属" data-testid="result-owner">拒绝归属：{{ castResult.拒绝归属 }}</p>
      <p v-if="castResult.被拒值" data-testid="result-rejected-value">被拒值：{{ castResult.被拒值 }}</p>
      <p v-if="castResult.重复提交" data-testid="duplicate-submit">重复提交：沿用原确认，未新增回执</p>
    </section>

    <section class="panel">
      <h3>提交自有换算系数</h3>
      <form class="analysis-form" @submit.prevent="submitOwn">
        <label>
          <span>目标单位</span>
          <input v-model="own.target_unit" data-testid="own-target-unit" />
        </label>
        <label>
          <span>系数</span>
          <input v-model="own.multiplier" data-testid="own-multiplier" />
        </label>
        <button class="btn" data-testid="own-submit" type="submit">登记自有系数</button>
      </form>
    </section>

    <section class="panel">
      <h3>同批来源规则冲突</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>冲突编号</th><th>批次</th><th>共享系数</th><th>自有系数</th>
            <th>已确认取值</th><th>状态</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="conflict in conflicts" :key="conflict.冲突编号" :data-testid="`conflict-${conflict.冲突编号}`">
            <td>{{ conflict.冲突编号 }}</td>
            <td>{{ conflict.关联批次 }}</td>
            <td>{{ conflict.共享系数 }}（{{ conflict.共享出处 }}）</td>
            <td>{{ conflict.自有系数 }}（{{ conflict.自有出处 }}）</td>
            <td>{{ conflict.已确认取值 }} {{ conflict.字段名称 }}</td>
            <td>{{ conflict.status }}</td>
            <td class="row-actions">
              <button
                v-if="conflict.status === '待裁决'"
                class="link"
                type="button"
                :data-testid="`resolve-own-${conflict.冲突编号}`"
                @click="resolve(conflict.冲突编号, '自有系数')"
              >
                保留自有
              </button>
              <button
                v-if="conflict.status === '待裁决'"
                class="link"
                type="button"
                :data-testid="`resolve-shared-${conflict.冲突编号}`"
                @click="resolve(conflict.冲突编号, '共享系数')"
              >
                保留共享
              </button>
            </td>
          </tr>
          <tr v-if="!conflicts.length">
            <td colspan="7" class="empty-state">本批没有来源规则冲突</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h3>历史转型回执</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>回执编号</th><th>渠道</th><th>申请类别</th><th>规则来源</th>
            <th>原始取值</th><th>归一取值</th><th>换算系数</th><th>系数出处</th>
            <th>确认</th><th>拒绝归属 / 被拒值</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="receipt in receipts" :key="receipt.回执编号" :data-testid="`receipt-${receipt.回执编号}`">
            <td>{{ receipt.回执编号 }}</td>
            <td>{{ receipt.请求渠道 }}</td>
            <td>{{ receipt.申请类别 }}</td>
            <td>{{ receipt.规则来源 }}</td>
            <td>{{ receipt.原始取值 }} {{ receipt.原始单位 }}</td>
            <td>{{ receipt.归一取值 }} {{ receipt.目标单位 }}</td>
            <td>{{ receipt.换算系数 || '—' }}</td>
            <td>{{ receipt.系数出处 || '—' }}</td>
            <td>{{ receipt.确认标记 }}{{ receipt.撤回时间 ? '（在途已撤回）' : '' }}</td>
            <td>
              <div v-if="receipt.拒绝归属">{{ receipt.拒绝归属 }}</div>
              <div v-if="receipt.被拒值">被拒值 {{ receipt.被拒值 }}</div>
              <span v-if="!receipt.拒绝归属 && !receipt.被拒值">—</span>
            </td>
          </tr>
          <tr v-if="!receipts.length">
            <td colspan="10" class="empty-state">暂无转型回执</td>
          </tr>
        </tbody>
      </table>
    </section>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'

import {
  type CastResultEntry,
  type ConflictRow,
  type ReceiptRow,
  type ShareEligibility,
  castValue,
  fetchConflicts,
  fetchEligibility,
  fetchReceipts,
  resolveConflict,
  submitOwnFactor,
  withdrawInFlight,
} from '@/api/unit-share'

const channels = ['web-upload', 'api-gateway-01', 'sftp-node-03', 'sftp-node-04']
const form = ref({
  channel: 'web-upload',
  field: 'net_weight',
  batch: 'FI-20260905001',
  source_unit: 'kg',
  raw_value: '2',
  grant_no: '',
})
const own = ref({ target_unit: 'g', multiplier: '1024' })
const preferred = ref('')
const eligibility = ref<ShareEligibility | null>(null)
const castResult = ref<(CastResultEntry & { message?: string }) | null>(null)
const receipts = ref<ReceiptRow[]>([])
const conflicts = ref<ConflictRow[]>([])
const errorMessage = ref('')
const notice = ref('')

const query = computed(() => ({
  channel: form.value.channel,
  field: form.value.field,
  batch: form.value.batch,
}))

async function refresh() {
  errorMessage.value = ''
  try {
    eligibility.value = await fetchEligibility({
      channel: form.value.channel,
      field: form.value.field,
      batch: form.value.batch,
      grant_no: form.value.grant_no,
      source_unit: form.value.source_unit,
    })
    await reloadHistory()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '资格核对失败'
  }
}

async function reloadHistory() {
  receipts.value = await fetchReceipts(query.value)
  conflicts.value = await fetchConflicts(form.value.batch)
}

async function submitCast() {
  errorMessage.value = ''
  notice.value = ''
  try {
    const result = await castValue({
      channel: form.value.channel,
      field: form.value.field,
      raw_value: form.value.raw_value,
      source_unit: form.value.source_unit,
      batch: form.value.batch,
      grant_no: form.value.grant_no,
      request_kind: eligibility.value?.在途申请.申请类别,
      preferred: preferred.value,
    })
    castResult.value = { ...(result.entry ?? {}), message: result.message }
    if (!result.ok) notice.value = result.message
    await refresh()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '取值转型提交失败'
  }
}

async function submitOwn() {
  errorMessage.value = ''
  notice.value = ''
  try {
    const result = await submitOwnFactor({
      channel: form.value.channel,
      field: form.value.field,
      source_unit: form.value.source_unit,
      target_unit: own.value.target_unit,
      multiplier: own.value.multiplier,
      batch: form.value.batch,
    })
    notice.value = result.message
    await refresh()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '自有系数提交失败'
  }
}

async function withdraw() {
  errorMessage.value = ''
  notice.value = ''
  try {
    const result = await withdrawInFlight(query.value)
    notice.value = result.message
    await refresh()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '撤回在途申请失败'
  }
}

async function resolve(conflictNo: string, keep: string) {
  errorMessage.value = ''
  try {
    const result = await resolveConflict(conflictNo, keep)
    notice.value = result.message
    await refresh()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '冲突裁决失败'
  }
}

watch(() => form.value.batch, () => {
  void refresh()
})

onMounted(refresh)
</script>
