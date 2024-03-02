
#include "utils/emp-tool.h"
#include <ctime>
#include <pthread.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <cstring>
#include <algorithm>
#include <vector>
#include <fstream>
#include <sstream>
#include <omp.h>
#include <time.h>
#include <unordered_map>
#include <unordered_set>
#include "RtreeBlocks/rt.h"
#include "RtreeBlocks/point.h"
#include "RtreeBlocks/rectangle.h"
#include "RtreeBlocks/rtnode.h"
#include "RtreeBlocks/rtdatanode.h"
#include "RtreeBlocks/rtdirnode.h"
using namespace sci;
using namespace std;

int partyNum, portS, portC, dim = 1 << 16;
string address = "127.0.0.1";
int Pd = 0, Pn = 0, Pst = 0, Pb = 3;
// int Pit = 0;
int THs = 4;
RT *tree1;
RT *tree2;
NetIO *Iot[4];
PRG128 prg;
CRH crh;
int BIT_SIZE = 32;
int BIT = BIT_SIZE;
uint64_t prime = 4294967291;
uint64_t primeT = prime / 2;
#define PARTY_A 1
#define PARTY_B 2
#define PARTY_C 3
int m = 2, depth, branch = 4;
int domain = 10000;
string file_prevM, file_prevQ, file_prevR;
int prev_party[] = {0, 3, 1, 2};
int next_party[] = {0, 2, 3, 1};
string SECURITY_TYPE = "Semi-honest"; //"Malicious"
double mal_time = 0, pre_time = 0, que_time = 0;
uint64_t *Verif_x, *Verif_y, *Verif_z, *Cmp_r, **Cmp_shares_r, *Cmp_alpha, *Cmp_beta;

uint64_t *RSSRect(uint64_t **v, int size, int th)
{
  uint64_t *a_prev = new uint64_t[size];
  uint64_t *a_next = new uint64_t[size];
  uint64_t *reconst = new uint64_t[size];
  for (int i = 0; i < size; i++)
  {
    a_next[i] = v[i][0];
    reconst[i] = (v[i][0] + v[i][1]) % prime;
  }
#pragma omp parallel num_threads(2)
  {
#pragma omp single
    {
#pragma omp task firstprivate(size)
      {
        Iot[th]->send_data(a_next, size * sizeof(uint64_t));
      }
#pragma omp task firstprivate(size)
      {
        Iot[th + 1]->recv_data(a_prev, size * sizeof(uint64_t));
      }
#pragma omp taskwait
    }
  }
  for (int i = 0; i < size; i++)
  {
    reconst[i] = (reconst[i] + a_prev[i]) % prime;
  }
  if (SECURITY_TYPE.compare("Malicious") == 0)
  {
    double startp = omp_get_wtime();
    uint64_t *b_prev = new uint64_t[size];
    uint64_t *b_next = new uint64_t[size];
    for (int i = 0; i < size; i++)
    {
      b_prev[i] = v[i][0];
    }
#pragma omp parallel num_threads(2)
    {
#pragma omp single
      {
#pragma omp task firstprivate(size)
        {
          Iot[th + 1]->send_data(b_prev, size * sizeof(uint64_t));
        }
#pragma omp task firstprivate(size)
        {
          Iot[th]->recv_data(b_next, size * sizeof(uint64_t));
        }
#pragma omp taskwait
      }
    }
    for (int i = 0; i < size; i++)
    {
      if (v[i][1] != b_next[i])
      {
        error("Malicious behaviour detected in Rect");
      }
    }
    delete[] b_prev;
    delete[] b_next;
    double endp = omp_get_wtime();
    mal_time += endp - startp;
  }
  delete[] a_prev;
  delete[] a_next;
  return reconst;
}

// uint64_t *RSSRect(vector<uint64_t *> v, int size, int th)
// {
//   uint64_t *a_prev = new uint64_t[size];
//   uint64_t *a_next = new uint64_t[size];
//   uint64_t *reconst = new uint64_t[size];
//   for (int i = 0; i < size; i++)
//   {
//     a_next[i] = v[i][0];
//     reconst[i] = (v[i][0] + v[i][1]) % prime;
//   }
// #pragma omp parallel num_threads(2)
//   {
// #pragma omp single
//     {
// #pragma omp task firstprivate(size)
//       {
//         Iot[th]->send_data(a_next, size * sizeof(uint64_t));
//       }
// #pragma omp task firstprivate(size)
//       {
//         Iot[th + 1]->recv_data(a_prev, size * sizeof(uint64_t));
//       }
// #pragma omp taskwait
//     }
//   }
//   for (int i = 0; i < size; i++)
//   {
//     reconst[i] = (reconst[i] + a_prev[i]) % prime;
//   }
//   if (SECURITY_TYPE.compare("Malicious") == 0)
//   {
//     double startp = omp_get_wtime();
//     uint64_t *b_prev = new uint64_t[size];
//     uint64_t *b_next = new uint64_t[size];
//     for (int i = 0; i < size; i++)
//     {
//       b_prev[i] = v[i][0];
//     }
// #pragma omp parallel num_threads(2)
//     {
// #pragma omp single
//       {
// #pragma omp task firstprivate(size)
//         {
//           Iot[th + 1]->send_data(b_prev, size * sizeof(uint64_t));
//         }
// #pragma omp task firstprivate(size)
//         {
//           Iot[th]->recv_data(b_next, size * sizeof(uint64_t));
//         }
// #pragma omp taskwait
//       }
//     }
//     for (int i = 0; i < size; i++)
//     {
//       if (b_prev[i] != b_next[i])
//       {
//         error("Malicious behaviour detected in Rect");
//       }
//     }
//     delete[] b_prev;
//     delete[] b_next;
//     double endp = omp_get_wtime();
//     mal_time += endp - startp;
//   }
//   delete[] a_prev;
//   delete[] a_next;
//   return reconst;
// }

uint64_t *RSSAdd(uint64_t *r1, uint64_t *r2)
{
  uint64_t *r = new uint64_t[2];
  r[0] = (r1[0] + r2[0]) % prime;
  r[1] = (r1[1] + r2[1]) % prime;
  return r;
}

uint64_t *RSSSum(uint64_t **r, int size)
{
  uint64_t *res = new uint64_t[2];
  res[0] = r[0][0];
  res[1] = r[0][1];
  for (int i = 1; i < size; i++)
  {
    res = RSSAdd(res, r[i]);
  }
  return res;
}

uint64_t **RSSAddVec(uint64_t **r1, uint64_t **r2, int size)
{
  uint64_t **res = new uint64_t *[size];
  for (int i = 0; i < size; i++)
  {
    res[i] = RSSAdd(r1[i], r2[i]);
  }
  return res;
}

uint64_t *RSSAddConst(uint64_t *r1, uint64_t r)
{
  uint64_t *res = new uint64_t[2];
  // memcpy(res, r1, 2 * sizeof(uint64_t));
  switch (partyNum)
  {
  case PARTY_A:
    res[0] = (r1[0] + r) % prime;
    res[1] = r1[1];
    break;
  case PARTY_B:
    res[0] = r1[0];
    res[1] = r1[1];
    break;
  case PARTY_C:
    res[0] = r1[0];
    res[1] = (r1[1] + r) % prime;
    break;
  }
  return res;
}

uint64_t *RSSSub(uint64_t *r1, uint64_t *r2)
{
  uint64_t *r = new uint64_t[2];
  r[0] = (prime + r1[0] - r2[0]) % prime;
  r[1] = (prime + r1[1] - r2[1]) % prime;
  return r;
}

uint64_t *RSSSubConst(uint64_t *r1, uint64_t r)
{
  uint64_t *res = new uint64_t[2];
  memcpy(res, r1, 2 * sizeof(uint64_t));
  switch (partyNum)
  {
  case PARTY_A:
    res[0] = (prime + res[0] - r) % prime;
    break;
  case PARTY_C:
    res[1] = (prime + res[1] - r) % prime;
    break;
  }
  return res;
}

uint64_t MUL(uint64_t r1, uint64_t r2)
{
  uint64_t res;
  if (r1 > primeT && r2 > primeT)
  {
    res = ((r1 * (r2 - primeT)) % prime + (r1 * primeT) % prime) % prime;
  }
  else
  {
    res = (r1 * r2) % prime;
  }
  return res;
}

uint64_t *RSSMulConst(uint64_t *r1, uint64_t r)
{
  uint64_t *res = new uint64_t[2];
  for (int i = 0; i < 2; i++)
  {
    res[i] = MUL(r1[i], r);
  }
  return res;
}

void funcCheckMaliciousMul(uint64_t *x, uint64_t *y, uint64_t *z, uint64_t **a, uint64_t **b, uint64_t **c, int th)
{
  double startp1 = omp_get_wtime();
  int size = 1;
  uint64_t **vecS = new uint64_t *[2 * size];
  uint64_t *rhoSigma = new uint64_t[2 * size];
  for (int i = 0; i < size; ++i)
  {
    vecS[i] = RSSSub(a[i], x);
    vecS[i + size] = RSSSub(b[i], y);
  }
  double startp2 = omp_get_wtime();
  rhoSigma = RSSRect(vecS, 2 * size, th);
  double startp3 = omp_get_wtime();
  uint64_t **mul_prev = new uint64_t *[size];
  uint64_t *mul_next = new uint64_t[size];
  // Doing x times sigma, rho times y, and rho times sigma
  for (int i = 0; i < size; i++)
  {
    mul_prev[i] = RSSSub(c[i], RSSAdd(z, RSSAdd(RSSMulConst(x, rhoSigma[i + size]), RSSAddConst(RSSMulConst(y, rhoSigma[i]), MUL(rhoSigma[i], rhoSigma[i + size])))));
  }
  double startp4 = omp_get_wtime();
  mul_next = RSSRect(mul_prev, size, th);
  double startp5 = omp_get_wtime();
  for (int i = 0; i < size; ++i)
    if (mul_next[i] != 0)
    {
      error("Malicious behaviour detected in Mul");
    }
  double startp6 = omp_get_wtime();
  mal_time += (startp6 - startp5) + (startp4 - startp3) + (startp2 - startp1);
  for (int i = 0; i < 2 * size; i++)
  {
    delete[] vecS[i];
  }
  for (int i = 0; i < size; i++)
  {
    delete[] mul_prev[i];
  }
  delete[] vecS;
  delete[] rhoSigma;
  delete[] mul_prev;
  delete[] mul_next;
}

uint64_t *RSSMul(uint64_t *r1, uint64_t *r2, int th)
{
  uint64_t *res = new uint64_t[2];
  res[0] = (MUL(r1[0], r2[0]) + MUL(r1[0], r2[1]) + MUL(r1[1], r2[0])) % prime;
  uint64_t *vecS = new uint64_t[1];
  vecS[0] = res[0];
  uint64_t *vecR = new uint64_t[1];
#pragma omp parallel num_threads(2)
  {
#pragma omp single
    {
#pragma omp task
      {
        Iot[th + 1]->send_data(vecS, sizeof(uint64_t));
      }
#pragma omp task
      {
        Iot[th]->recv_data(vecR, sizeof(uint64_t));
      }
#pragma omp taskwait
    }
  }
  res[1] = vecR[0];
  delete[] vecS;
  delete[] vecR;
  return res;
}

uint64_t *RSSXOR(uint64_t *r1, uint64_t *r2, int th)
{
  return RSSSub(RSSAdd(r1, r2), RSSMulConst(RSSMul(r1, r2, th), 2));
}

uint64_t *RSSXORConst(uint64_t *r1, uint64_t r)
{
  return RSSSub(RSSAddConst(r1, r), RSSMulConst(r1, 2 * r));
}

void funcCheckMaliciousDotProd(uint64_t *x, uint64_t *y, uint64_t *z, uint64_t **a, uint64_t **b, uint64_t **c, int size, int th)
{
  double startp1 = omp_get_wtime();
  uint64_t **vecS = new uint64_t *[2 * size];
  uint64_t *rhoSigma = new uint64_t[2 * size];
  for (int i = 0; i < size; ++i)
  {
    vecS[i] = RSSSub(a[i], x);
    vecS[i + size] = RSSSub(b[i], y);
  }
  double startp2 = omp_get_wtime();
  rhoSigma = RSSRect(vecS, 2 * size, th);
  double startp3 = omp_get_wtime();
  uint64_t **mul_prev = new uint64_t *[size];
  uint64_t *mul_next = new uint64_t[size];
  // Doing x times sigma, rho times y, and rho times sigma
  for (int i = 0; i < size; i++)
  {
    mul_prev[i] = RSSSub(c[i], RSSAdd(z, RSSAdd(RSSMulConst(x, rhoSigma[i + size]), RSSAddConst(RSSMulConst(y, rhoSigma[i]), MUL(rhoSigma[i], rhoSigma[i + size])))));
  }
  double startp4 = omp_get_wtime();
  mul_next = RSSRect(mul_prev, size, th);
  double startp5 = omp_get_wtime();
  for (int i = 0; i < size; ++i)
    if (mul_next[i] != 0)
    {
      error("Malicious behaviour detected in Mul");
    }
  double startp6 = omp_get_wtime();
  mal_time += (startp6 - startp5) + (startp4 - startp3) + (startp2 - startp1);
  for (int i = 0; i < 2 * size; i++)
  {
    delete[] vecS[i];
  }
  for (int i = 0; i < size; i++)
  {
    delete[] mul_prev[i];
  }
  delete[] vecS;
  delete[] rhoSigma;
  delete[] mul_prev;
  delete[] mul_next;
}

uint64_t **RSSDotMul(uint64_t **r1, uint64_t **r2, int size, int th)
{
  uint64_t **res = new uint64_t *[size];
  uint64_t *vecS = new uint64_t[size];
  uint64_t *vecR = new uint64_t[size];
  for (int i = 0; i < size; i++)
  {
    uint64_t tmp = (MUL(r1[i][0], r2[i][0]) + MUL(r1[i][0], r2[i][1]) + MUL(r1[i][1], r2[i][0])) % prime;
    vecS[i] = tmp;
  }
#pragma omp parallel num_threads(2)
  {
#pragma omp single
    {
#pragma omp task firstprivate(size)
      {
        Iot[th + 1]->send_data(vecS, size * sizeof(uint64_t));
      }
#pragma omp task firstprivate(size)
      {
        Iot[th]->recv_data(vecR, size * sizeof(uint64_t));
      }
#pragma omp taskwait
    }
  }
  for (int i = 0; i < size; i++)
  {
    res[i] = new uint64_t[2];
    res[i][0] = vecS[i];
    res[i][1] = vecR[i];
  }
  delete[] vecS;
  delete[] vecR;
  if (SECURITY_TYPE.compare("Malicious") == 0)
    funcCheckMaliciousDotProd(Verif_x, Verif_y, Verif_z, r1, r2, res, size, th);
  return res;
}

void loadP(vector<vector<uint64_t>> &p, string data_path)
{
  ifstream inf;
  inf.open(data_path);
  string line;
  while (getline(inf, line))
  {
    istringstream sin(line);
    // cout << line << endl;
    vector<uint64_t> lineArray;
    string field;
    while (getline(sin, field, ','))
    {
      lineArray.push_back(stoi(field));
    }
    p.push_back(lineArray);
    lineArray.clear();
  }
  inf.close();
}
uint64_t *plainT(vector<vector<uint64_t>> P, uint64_t *Q, int n, int m)
{
  unordered_map<uint32_t, vector<uint64_t>> T;
  unordered_map<uint32_t, vector<uint64_t>> Result;
  // Process
  double t1 = omp_get_wtime();
  for (int i = 0; i < n; i++)
  {
    vector<uint64_t> pt(m);
    for (int j = 0; j < m; j++)
    {
      if (j < 2)
      {
        // Q is scaled to 2times, require Q/2;
        uint64_t t = P[i][j] - Q[j] / 2;
        pt[j] = t * t;
      }
      else
      { // location
        pt[j] = P[i][j];
      }
    }
    T[i] = pt;
  }
  // for (auto &entry : T) {
  //     for (int j = 0; j < m; j++) {
  //       cout << entry.second[j]<<",";
  //     }
  //     cout << endl;
  //   }
  double er = omp_get_wtime();
  double plain_process = er - t1;
  // Select
  while (!T.empty())
  {
    n = T.size();
    vector<vector<uint64_t>> S(n, vector<uint64_t>(2));
    int i0 = 0;
    for (auto &entry : T)
    {
      S[i0][0] = entry.first;
      vector<uint64_t> s = entry.second;
      S[i0][1] = s[0];
      for (int j = 1; j < m; j++)
      {
        S[i0][1] = S[i0][1] + s[j];
      }
      i0++;
    }
    int pos = S[0][0];
    uint64_t STMin = S[0][1];
    for (int i = 1; i < n; i++)
    {
      if (S[i][1] < STMin)
      {
        STMin = S[i][1];
        pos = S[i][0];
      }
    }
    vector<uint64_t> Pmin = P[pos];
    vector<uint64_t> Tmin = T[pos];
    Result[Result.size()] = Pmin;
    for (auto it = T.begin(); it != T.end();)
    {
      vector<uint64_t> s = it->second;
      int sdom;
      vector<uint64_t> leq(m);
      for (int j = 0; j < m; j++)
      {
        leq[j] = (Tmin[j] <= s[j]) ? 1 : 0;
      }
      uint64_t LEQ = leq[0];
      for (int j = 1; j < m; j++)
      {
        LEQ = LEQ * leq[j];
      }
      uint64_t EQ = 0;
      uint64_t tmp = 0;
      for (int j = 0; j < m; j++)
      {
        tmp = tmp + s[j];
      }
      if (STMin < tmp)
      {
        EQ = 1;
      }
      sdom = LEQ * EQ;
      if (sdom == 1)
      {
        it = T.erase(it);
      }
      else
      {
        ++it;
      }
    }
    T.erase(pos);
  }
  int k = Result.size();
  cout << k << endl;
  uint64_t *resD = new uint64_t[k * m];
  for (int i = 0; i < k; i++)
  {
    for (int j = 0; j < m; j++)
    {
      resD[i * m + j] = Result[i][j];
    }
  }
  return resD;
}

uint64_t getMSB(uint64_t a)
{
  return (a > primeT) ? 1L : 0L;
}

uint64_t wrapAround(uint64_t a, uint64_t b)
{
  return ((a + b) >= prime) ? 1L : 0L;
}

uint64_t wrap3(uint64_t a, uint64_t b, uint64_t c)
{
  uint64_t temp = (a + b) % prime;
  if (wrapAround(a, b) == 1)
    return 1 - wrapAround(temp, c);
  else
    return wrapAround(temp, c);
}

uint64_t *wrap3(uint64_t **a, uint64_t *b, int size)
{
  uint64_t *c = new uint64_t[size];
  for (int i = 0; i < size; ++i)
    c[i] = wrap3(a[i][0], a[i][1], b[i]);
  return c;
}

void read_model(RT *tree, string data_path)
{
  ifstream inf;
  inf.open(data_path);
  string line;
  getline(inf, line);
  // istringstream sin0(line);
  // cout << line << endl;
  int rootlevel = depth - 1;
  tree->nodeCapacity = branch;
  int levt = 1;
  int leaf = 0;
  tree->leafNum = 0;
  tree->nodeNum = 0;
  RTDirNode *rDirNode = new RTDirNode(tree->nodeCapacity, nullptr, rootlevel);
  tree->setRoot(rDirNode);
  RTNode *rootnode = rDirNode;
  string *lineArray = new string[4];
  while (getline(inf, line))
  {
    // cout << line << endl;
    tree->nodeNum++;
    int level = 0;
    while (line.at(level) == '+')
    {
      level++;
    }
    istringstream sin(line);
    string field;
    int j = 0;
    while (getline(sin, field, ';'))
    {
      lineArray[j] = field;
      j++;
    }
    if (level > 0)
    {
      istringstream sin1(lineArray[0].substr(level, lineArray[0].size() - level));
      string mbr_t;
      j = 0;
      uint64_t *t1 = new uint64_t[2];
      while (getline(sin1, mbr_t, ','))
      {
        t1[j] = strtoull(mbr_t.c_str(), NULL, 10);
        j++;
      }
      istringstream sin2(lineArray[1]);
      j = 0;
      uint64_t *t2 = new uint64_t[2];
      while (getline(sin2, mbr_t, ','))
      {
        t2[j] = strtoull(mbr_t.c_str(), NULL, 10);
        j++;
      }
      Point *p1 = new Point(t1, 2);
      Point *p2 = new Point(t2, 2);
      Rectangle *rect = new Rectangle(p1, p2);
      if (levt < level)
      {
        RTDirNode *DirNode = new RTDirNode(tree->nodeCapacity, rootnode, rootnode->level - 1);
        ((RTDirNode *)rootnode)->children.push_back(DirNode);
        DirNode->addData(rect);
        rootnode = (RTNode *)DirNode;
        levt = level;
        leaf = 0;
      }
      else if (levt > level)
      {
        RTDirNode *rDirNodet = (RTDirNode *)rootnode->getParent();
        int ll = levt - level;
        while (ll > 1)
        {
          rDirNodet = (RTDirNode *)rDirNodet->getParent();
          ll--;
        }
        rDirNodet->addData(rect);
        rootnode = rDirNodet;
        levt = level;
        leaf = 0;
      }
      else
      {
        rootnode->addData(rect);
        levt = level;
        leaf = 0;
      }
    }
    else
    {
      tree->leafNum++;
      istringstream sin1(lineArray[0].substr(levt, lineArray[0].size() - levt));
      string mbr_t;
      j = 0;
      uint64_t *t1 = new uint64_t[2];
      while (getline(sin1, mbr_t, ','))
      {
        t1[j] = strtoull(mbr_t.c_str(), NULL, 10);
        j++;
      }
      istringstream sin2(lineArray[1]);
      j = 0;
      uint64_t *t2 = new uint64_t[2];
      while (getline(sin2, mbr_t, ','))
      {
        t2[j] = strtoull(mbr_t.c_str(), NULL, 10);
        j++;
      }
      istringstream sin3(lineArray[2]);
      j = 0;
      uint64_t *pt = new uint64_t[m];
      while (getline(sin3, mbr_t, ','))
      {
        pt[j] = strtoull(mbr_t.c_str(), NULL, 10);
        j++;
      }
      Point *p1 = new Point(t1, 2);
      Point *p2 = new Point(t2, 2);
      Rectangle *rect = new Rectangle(p1, p2);
      if (leaf == 0)
      {
        RTDataNode *rNode = new RTDataNode(tree->nodeCapacity, rootnode);
        ((RTDirNode *)rootnode)->children.push_back(rNode);
        rNode->addDataP(rect, new Point(pt, m));
        rootnode = rNode;
        leaf = 1;
      }
      else
      {
        rootnode->addDataP(rect, new Point(pt, m));
        if (lineArray[3].at(0) == '0')
        {
          leaf = 1;
        }
        else
        {
          rootnode = (rootnode->getParent());
          leaf = 0;
        }
      }
    }
    // cout<<"tTTT:";
    // tree->printRT(rDirNode, 0);
    // cout<<endl;
  }
  // tree->getRoot(tree->root);
  // delete[] lineArray0;
  delete[] lineArray;
  inf.close();
}

void read_Query(vector<string> fileNames, uint64_t ***&SS_Q, int size)
{
#pragma omp parallel num_threads(2)
  {
#pragma omp single
    {
#pragma omp task firstprivate(fileNames)
      {
        ifstream inf0;
        inf0.open(fileNames[0]);
        string line0;
        int k = 0;
        while (getline(inf0, line0))
        {
          istringstream sin0(line0);
          string field0;
          int j = 0;
          while (getline(sin0, field0, ','))
          {
            SS_Q[k][j][0] = strtoull(field0.c_str(), NULL, 10);
            j++;
          }
          k++;
        }
        inf0.close();
      }
#pragma omp task firstprivate(fileNames)
      {
        ifstream inf1;
        inf1.open(fileNames[1]);
        string line1;
        int k = 0;
        while (getline(inf1, line1))
        {
          istringstream sin1(line1);
          string field1;
          int j = 0;
          while (getline(sin1, field1, ','))
          {
            SS_Q[k][j][1] = strtoull(field1.c_str(), NULL, 10);
            j++;
          }
          k++;
        }
        inf1.close();
      }
#pragma omp taskwait
    }
  }
}

void read_Random(vector<string> fileNames, uint64_t *&r, uint64_t **&shares_r, uint64_t *&alpha, uint64_t *&beta, uint64_t *&x, uint64_t *&y, uint64_t *&z)
{
  // cout << "read_Random" << endl;
  for (int i = 0; i < BIT_SIZE; i++)
  {
    shares_r[i] = new uint64_t[2];
  }
#pragma omp parallel num_threads(2)
  {
#pragma omp single
    {
#pragma omp task firstprivate(fileNames)
      {
        ifstream inf0;
        inf0.open(fileNames[0]);
        string line0;
        getline(inf0, line0);
        istringstream sin0(line0);
        string field0;
        getline(sin0, field0, ';');
        int size = stoi(field0);
        int sizeLong = size * BIT_SIZE;
        // wrap_r for wrap3
        string line1;
        getline(inf0, line1);
        istringstream sin1(line1);
        string field1;
        getline(sin1, field1, ',');
        r[0] = strtoull(field1.c_str(), NULL, 10);
        // bits_of_r for wrap3
        string line2;
        getline(inf0, line2);
        istringstream sin2(line2);
        string field2;
        int j = 0;
        while (getline(sin2, field2, ','))
        {
          shares_r[j][0] = strtoull(field2.c_str(), NULL, 10);
          j++;
        }
        // alpha for wrap3
        string line3;
        getline(inf0, line3);
        istringstream sin3(line3);
        string field3;
        getline(sin3, field3, ',');
        alpha[0] = strtoull(field3.c_str(), NULL, 10);
        // plain_beta for comparison
        string line4;
        getline(inf0, line4);
        istringstream sin4(line4);
        string field4;
        getline(sin4, field4, ',');
        beta[0] = strtoull(field4.c_str(), NULL, 10);
        // x for verify
        string line5;
        getline(inf0, line5);
        istringstream sin5(line5);
        string field5;
        getline(sin5, field5, ',');
        x[0] = strtoull(field5.c_str(), NULL, 10);
        // y for verify
        string line6;
        getline(inf0, line6);
        istringstream sin6(line6);
        string field6;
        getline(sin6, field6, ',');
        y[0] = strtoull(field6.c_str(), NULL, 10);
        // z for verify
        string line7;
        getline(inf0, line7);
        istringstream sin7(line7);
        string field7;
        getline(sin7, field7, ',');
        z[0] = strtoull(field7.c_str(), NULL, 10);
        inf0.close();
      }
#pragma omp task firstprivate(fileNames)
      {
        ifstream inf1;
        inf1.open(fileNames[1]);
        string line0;
        getline(inf1, line0);
        istringstream sin0(line0);
        string field0;
        getline(sin0, field0, ';');
        int size = stoi(field0);
        int sizeLong = size * BIT_SIZE;
        // wrap_r for wrap3
        string line1;
        getline(inf1, line1);
        istringstream sin1(line1);
        string field1;
        getline(sin1, field1, ',');
        r[1] = strtoull(field1.c_str(), NULL, 10);
        // bits_of_r for wrap3
        string line2;
        getline(inf1, line2);
        istringstream sin2(line2);
        string field2;
        int j = 0;
        while (getline(sin2, field2, ','))
        {
          shares_r[j][1] = strtoull(field2.c_str(), NULL, 10);
          j++;
        }
        // alpha for wrap3
        string line3;
        getline(inf1, line3);
        istringstream sin3(line3);
        string field3;
        getline(sin3, field3, ',');
        alpha[1] = strtoull(field3.c_str(), NULL, 10);
        // plain_beta for comparison
        string line4;
        getline(inf1, line4);
        istringstream sin4(line4);
        string field4;
        getline(sin4, field4, ',');
        beta[1] = strtoull(field4.c_str(), NULL, 10);
        // x for verify
        string line5;
        getline(inf1, line5);
        istringstream sin5(line5);
        string field5;
        getline(sin5, field5, ',');
        x[1] = strtoull(field5.c_str(), NULL, 10);
        // y for verify
        string line6;
        getline(inf1, line6);
        istringstream sin6(line6);
        string field6;
        getline(sin6, field6, ',');
        y[1] = strtoull(field6.c_str(), NULL, 10);
        // z for verify
        string line7;
        getline(inf1, line7);
        istringstream sin7(line7);
        string field7;
        getline(sin7, field7, ',');
        z[1] = strtoull(field7.c_str(), NULL, 10);
        inf1.close();
      }
#pragma omp taskwait
    }
  }
}

// Multiply index 2i, 2i+1 of the first vector into the second one. The second vector is half the size.
uint64_t **funcMultiplyNeighbours(uint64_t **c_1, int size, int th)
{
  uint64_t **t1 = new uint64_t *[size / 2];
  uint64_t **t2 = new uint64_t *[size / 2];
  for (int i = 0; i < size / 2; ++i)
  {
    t1[i] = c_1[2 * i];
    t2[i] = c_1[2 * i + 1];
  }
  return RSSDotMul(t1, t2, size / 2, th);
}

uint64_t *funcCrunchMultiply(uint64_t **c, int size, int sizeLong, int th)
{
  uint64_t **c_0 = c;
  uint64_t **res = new uint64_t *[size];
  uint64_t *betaPrime = new uint64_t[size];

  while (sizeLong > size)
  {
    res = funcMultiplyNeighbours(c_0, sizeLong, th);
    sizeLong /= 2;
    c_0 = new uint64_t *[sizeLong];
    for (int i = 0; i < sizeLong; i++)
    {
      c_0[i] = res[i];
    }
  }
  uint64_t *re_const = RSSRect(res, size, th);
  for (int i = 0; i < size; ++i)
  {
    betaPrime[i] = (re_const[i] == 0) ? 1L : 0L;
  }
  delete[] re_const;
  for (int i = 0; i < size; ++i)
  {
    delete[] res[i];
  }
  delete[] res;
  return betaPrime;
}

uint64_t **funcCrunchXOR(uint64_t **beta, int size, int th)
{
  uint64_t **beta1 = new uint64_t *[size];
  uint64_t **beta2 = new uint64_t *[size];
  uint64_t **beta3 = new uint64_t *[size];
  uint64_t **res = new uint64_t *[size];
  for (int i = 0; i < size; ++i)
  {
    beta1[i] = new uint64_t[2];
    beta2[i] = new uint64_t[2];
    beta3[i] = new uint64_t[2];
  }
  // beta1 + beta2 + beta3
  if (partyNum == PARTY_A)
  {
    for (int i = 0; i < size; ++i)
    {
      beta1[i][0] = beta[i][0];
      beta1[i][1] = 0L;
      beta2[i][0] = 0L;
      beta2[i][1] = beta[i][1];
      beta3[i][0] = 0L;
      beta3[i][1] = 0L;
    }
  }
  else if (partyNum == PARTY_B)
  {
    for (int i = 0; i < size; ++i)
    {
      beta1[i][0] = 0L;
      beta1[i][1] = 0L;
      beta2[i][0] = beta[i][0];
      beta2[i][1] = 0L;
      beta3[i][0] = 0L;
      beta3[i][1] = beta[i][1];
    }
  }
  else if (partyNum == PARTY_C)
  {
    for (int i = 0; i < size; ++i)
    {
      beta1[i][0] = 0L;
      beta1[i][1] = beta[i][1];
      beta2[i][0] = 0L;
      beta2[i][1] = 0L;
      beta3[i][0] = beta[i][0];
      beta3[i][1] = 0L;
    }
  }
  for (int i = 0; i < size; ++i)
  {
    res[i] = RSSXOR(RSSXOR(beta1[i], beta2[i], th), beta3[i], th);
  }
  for (int i = 0; i < size; ++i)
  {
    delete[] beta1[i];
    delete[] beta2[i];
    delete[] beta3[i];
  }
  delete[] beta1;
  delete[] beta2;
  delete[] beta3;
  return res;
}

uint64_t **funcLoopMultiply(uint64_t **c, int size, int m, int th)
{
  int len = size / m;
  uint64_t **res = new uint64_t *[len];
  for (int i = 0; i < len; ++i)
  {
    res[i] = c[m * i];
  }
  uint64_t **c_0 = new uint64_t *[len];
  int k = 1;
  while (k < m)
  {
    for (int i = 0; i < len; ++i)
    {
      c_0[i] = c[m * i + k];
    }
    res = RSSDotMul(c_0, res, len, th);
    k++;
  }
  return res;
}

uint64_t **funcPrivateCompare(uint64_t **share_m, uint64_t *r, uint64_t *beta, int size, int th)
{
  int sizeLong = size * BIT_SIZE;
  int index_t = 0;
  uint64_t **c = new uint64_t *[sizeLong];
  uint64_t **diff = new uint64_t *[sizeLong];
  uint64_t **twoBetaMinusOne = new uint64_t *[sizeLong];
  uint64_t *bit_r = new uint64_t[sizeLong];
  uint64_t *rss = new uint64_t[2];
  for (int i = 0; i < size; ++i)
  {
    // Computing 2Beta-1, where the betaprime equal 0
    int index = i * BIT_SIZE;
    rss = RSSSubConst(RSSAdd(beta, beta), 1L);
    for (int k = 0; k < BIT_SIZE; ++k)
    {
      index_t = index + k;
      twoBetaMinusOne[index_t] = new uint64_t[2];
      for (int j = 0; j < 2; j++)
      {
        twoBetaMinusOne[index_t][j] = rss[j];
      }
      bit_r[index_t] = (r[i] >> (BIT_SIZE - 1 - k)) & 1;
      diff[index_t] = RSSSubConst(share_m[k], bit_r[index_t]);
    }
  }
  uint64_t **xMinusR = RSSDotMul(diff, twoBetaMinusOne, sizeLong, th);
  // uint64_t *plain_diff = RSSRect(diff, sizeLong, th);
  // cout << "plain_diff: \t\n ";
  // for (int i = 0; i < sizeLong; ++i)
  //   cout << plain_diff[i] << " ";
  // cout << endl;
  // uint64_t *plain_twoBetaMinusOne = RSSRect(twoBetaMinusOne, sizeLong, th);
  // cout << "plain_twoBetaMinusOne: \t\n ";
  // for (int i = 0; i < sizeLong; ++i)
  //   cout << plain_twoBetaMinusOne[i] << " ";
  // cout << endl;
  // uint64_t *plain_xMinusR = RSSRect(xMinusR, sizeLong, th);
  // cout << "plain_xMinusR: \t\n ";
  // for (int i = 0; i < sizeLong; ++i)
  //   cout << plain_xMinusR[i] << " ";
  // cout << endl;
  uint64_t *a = new uint64_t[2];
  uint64_t *w = new uint64_t[2];
  for (int i = 0; i < size; ++i)
  {
    memset(a, 0, 2 * sizeof(uint64_t));
    int index = i * BIT_SIZE;
    for (int k = 0; k < BIT_SIZE; ++k)
    {
      index_t = index + k;
      c[index_t] = RSSAdd(RSSAddConst(xMinusR[index_t], 1L), a);
      w = RSSXORConst(share_m[k], bit_r[index_t]);
      a = RSSAdd(a, w);
    }
  }
  uint64_t *betaPrime = funcCrunchMultiply(c, size, sizeLong, th);
  uint64_t **cmp = new uint64_t *[size];
  for (int i = 0; i < size; i++)
  {
    cmp[i] = RSSXORConst(beta, betaPrime[i]);
  }
  for (int i = 0; i < sizeLong; ++i)
  {
    delete[] xMinusR[i];
    delete[] c[i];
    delete[] diff[i];
    delete[] twoBetaMinusOne[i];
  }
  delete[] xMinusR;
  delete[] c;
  delete[] diff;
  delete[] twoBetaMinusOne;
  delete[] bit_r;
  delete[] rss;
  delete[] a;
  delete[] w;
  delete[] betaPrime;
  return cmp;
}

/*
//old
uint64_t **funcWrap(uint64_t **a, uint64_t *betaPC, uint64_t *r, uint64_t **shares_r, uint64_t *alpha, int size, int th)
{
  uint64_t **theta = new uint64_t *[size];
  uint64_t **x = new uint64_t *[size];
  uint64_t **beta = new uint64_t *[size];
  for (int i = 0; i < size; ++i)
  {
    beta[i] = new uint64_t[2];
    for (int j = 0; j < 2; j++)
    {
      beta[i][j] = wrapAround(a[i][j], r[j]);
    }
    // funcPrivateCompare:x need to add betaPC for betaPC=1,SecureNN
    x[i] = RSSAdd(a[i], r);
  }
  uint64_t *x_prev = new uint64_t[size];
  uint64_t *reconst_x = RSSRect(x, size, th);
  for (int i = 0; i < size; i++)
  {
    x_prev[i] = (reconst_x[i] + (prime - x[i][0]) + (prime - x[i][1])) % prime;
    reconst_x[i] = (reconst_x[i] + 1L) % prime; // r > x, need add 1
  }
  uint64_t *delta = wrap3(x, x_prev, size); // All parties have plain delta

  // cout << "PC: \t\t" << funcTime(funcPrivateCompare, shares_r, reconst_x, eta, etaPrime, size, BIT_SIZE) << endl;
  uint64_t **eta = funcPrivateCompare(shares_r, reconst_x, betaPC, size, th);
  // uint64_t *plain_a = RSSRect(a, size, th);
  // uint64_t *plain_r = RSSRect(r, size, th);
  // uint64_t *plain_eta = RSSRect(eta, size, th);
  // cout << "ss_beta: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << beta[i][0] << " ";
  // cout << endl;
  // cout << "ss_alpha: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << alpha[i][0] << " ";
  // cout << endl;
  // cout << "plain_a: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << plain_a[i] << " ";
  // cout << endl;
  // cout << "plain_r: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << plain_r[i] << " ";
  // cout << endl;
  // cout << "plain_x: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << reconst_x[i] << " ";
  // cout << endl;
  // cout << "diff_eta: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   if (plain_r[i] >= reconst_x[i])
  //   {
  //     cout << plain_eta[i] << " ";
  //   }
  //   else
  //   {
  //     cout << (1 - plain_eta[i]) << " ";
  //   }
  // }
  // cout << endl;
  // cout << "plain_eta: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   if (plain_r[i] >= reconst_x[i])
  //   {
  //     cout << 1 << " ";
  //   }
  //   else
  //   {
  //     cout << 0 << " ";
  //   }
  // }
  // cout << endl;
  // cout << "new_eta: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << (plain_eta[i]) << " ";
  // }
  // cout << endl;

  uint64_t **betaXOR = funcCrunchXOR(beta, size, th);
  // uint64_t *plain_betaXOR = RSSRect(betaXOR, size, th);
  // cout << "plain_betaXOR: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << (plain_betaXOR[i]) << " ";
  // }
  // cout << endl;
  // cout << "plain_delta: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << (delta[i]) << " ";
  // }
  // cout << endl;
  // uint64_t *plain_alpha = RSSRect(alpha, size, th);
  // cout << "plain_alpha: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << (plain_alpha[i]) << " ";
  // }
  // cout << endl;
  for (int i = 0; i < size; ++i)
  {
    theta[i] = RSSXOR(RSSXOR(RSSXORConst(betaXOR[i], delta[i]), eta[i], th), alpha, th);
  }
  for (int i = 0; i < size; i++)
  {
    delete[] x[i];
    delete[] beta[i];
    delete[] eta[i];
    delete[] betaXOR[i];
  }
  delete[] x;
  delete[] beta;
  delete[] x_prev;
  delete[] reconst_x;
  delete[] delta;
  delete[] eta;
  delete[] betaXOR;
  return theta;
}

uint64_t **funcMsb(uint64_t **a, uint64_t *r, uint64_t **shares_r, uint64_t *alpha, uint64_t *beta, int size, int th)
{
  // cout << "funcMsb" << endl;
  uint64_t **cmp;
  uint64_t **twoA = new uint64_t *[size];
  // uint64_t *plain_a = RSSRect(a, size, th);
  // cout << "plain_a: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   if (plain_a[i] > primeT)
  //   {
  //     cout << "-" << (prime - plain_a[i]) << " ";
  //   }
  //   else
  //   {
  //     cout << plain_a[i] << " ";
  //   }
  // }
  // cout << endl;
  for (int i = 0; i < size; i++)
  {
    twoA[i] = RSSMulConst(a[i], 2L);
  }
  // uint64_t *plain_twoA = RSSRect(twoA, size, th);
  // cout << "plain_twoA: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   if (plain_twoA[i] > primeT)
  //   {
  //     cout << "-" << (prime - plain_twoA[i]) << " ";
  //   }
  //   else
  //   {
  //     cout << plain_twoA[i] << " ";
  //   }
  // }
  // cout << endl;
  cmp = funcWrap(twoA, beta, r, shares_r, alpha, size, th);
  // uint64_t *plain_cmp = RSSRect(cmp, size, th);
  // cout << "plain_cmp: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << plain_cmp[i] << " ";
  // }
  // cout << endl;
  uint64_t **tmp = new uint64_t *[size];
  for (int i = 0; i < size; i++)
  {
    tmp[i] = new uint64_t[2];
    for (int j = 0; j < 2; j++)
    {
      tmp[i][j] = getMSB(a[i][j]);
    }
  }
  uint64_t **msbXOR = funcCrunchXOR(tmp, size, th);
  for (int i = 0; i < size; i++)
  {
    cmp[i] = RSSXOR(msbXOR[i], cmp[i], th);
  }
  for (int i = 0; i < size; i++)
  {
    delete[] twoA[i];
    delete[] tmp[i];
    delete[] msbXOR[i];
  }
  delete[] twoA;
  delete[] tmp;
  delete[] msbXOR;
  return cmp;
}
*/

// >p/2 is 1(negative)
uint64_t **funcWrap(uint64_t **a, uint64_t *betaPC, uint64_t *r, uint64_t **shares_r, uint64_t *alpha, uint64_t **tmp, int size, int th)
{
  uint64_t **theta = new uint64_t *[size];
  uint64_t **x = new uint64_t *[size];
  uint64_t **beta = new uint64_t *[size];
  for (int i = 0; i < size; ++i)
  {
    beta[i] = new uint64_t[2];
    for (int j = 0; j < 2; j++)
    {
      beta[i][j] = wrapAround(a[i][j], r[j]);
      beta[i][j] = beta[i][j] + tmp[i][j] - 2 * beta[i][j] * tmp[i][j];
    }
    // funcPrivateCompare:x need to add betaPC for betaPC=1,SecureNN
    x[i] = RSSAdd(a[i], r);
  }
  uint64_t *x_prev = new uint64_t[size];
  uint64_t *reconst_x = RSSRect(x, size, th);
  for (int i = 0; i < size; i++)
  {
    x_prev[i] = (reconst_x[i] + (prime - x[i][0]) + (prime - x[i][1])) % prime;
    reconst_x[i] = (reconst_x[i] + 1L) % prime; // r > x, need add 1
  }
  uint64_t *delta = wrap3(x, x_prev, size); // All parties have plain delta

  // cout << "PC: \t\t" << funcTime(funcPrivateCompare, shares_r, reconst_x, eta, etaPrime, size, BIT_SIZE) << endl;
  uint64_t **eta = funcPrivateCompare(shares_r, reconst_x, betaPC, size, th);
  // uint64_t *plain_a = RSSRect(a, size, th);
  // uint64_t *plain_r = RSSRect(r, size, th);
  // uint64_t *plain_eta = RSSRect(eta, size, th);
  // cout << "ss_beta: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << beta[i][0] << " ";
  // cout << endl;
  // cout << "ss_alpha: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << alpha[i][0] << " ";
  // cout << endl;
  // cout << "plain_a: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << plain_a[i] << " ";
  // cout << endl;
  // cout << "plain_r: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << plain_r[i] << " ";
  // cout << endl;
  // cout << "plain_x: \t\n ";
  // for (int i = 0; i < size; ++i)
  //   cout << reconst_x[i] << " ";
  // cout << endl;
  // cout << "diff_eta: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   if (plain_r[i] >= reconst_x[i])
  //   {
  //     cout << plain_eta[i] << " ";
  //   }
  //   else
  //   {
  //     cout << (1 - plain_eta[i]) << " ";
  //   }
  // }
  // cout << endl;
  // cout << "plain_eta: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   if (plain_r[i] >= reconst_x[i])
  //   {
  //     cout << 1 << " ";
  //   }
  //   else
  //   {
  //     cout << 0 << " ";
  //   }
  // }
  // cout << endl;
  // cout << "new_eta: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << (plain_eta[i]) << " ";
  // }
  // cout << endl;

  uint64_t **betaXOR = funcCrunchXOR(beta, size, th);
  // uint64_t *plain_betaXOR = RSSRect(betaXOR, size, th);
  // cout << "plain_betaXOR: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << (plain_betaXOR[i]) << " ";
  // }
  // cout << endl;
  // cout << "plain_delta: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << (delta[i]) << " ";
  // }
  // cout << endl;
  // uint64_t *plain_alpha = RSSRect(alpha, size, th);
  // cout << "plain_alpha: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << (plain_alpha[i]) << " ";
  // }
  // cout << endl;
  for (int i = 0; i < size; ++i)
  {
    theta[i] = RSSXOR(RSSXOR(RSSXORConst(betaXOR[i], delta[i]), eta[i], th), alpha, th);
  }
  for (int i = 0; i < size; i++)
  {
    delete[] x[i];
    delete[] beta[i];
    delete[] eta[i];
    delete[] betaXOR[i];
  }
  delete[] x;
  delete[] beta;
  delete[] x_prev;
  delete[] reconst_x;
  delete[] delta;
  delete[] eta;
  delete[] betaXOR;
  return theta;
}

uint64_t **funcMsb(uint64_t **a, uint64_t *r, uint64_t **shares_r, uint64_t *alpha, uint64_t *beta, int size, int th)
{
  // cout << "funcMsb" << endl;
  uint64_t **cmp;
  uint64_t **twoA = new uint64_t *[size];
  // uint64_t *plain_a = RSSRect(a, size, th);
  // cout << "plain_a: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   if (plain_a[i] > primeT)
  //   {
  //     cout << "-" << (prime - plain_a[i]) << " ";
  //   }
  //   else
  //   {
  //     cout << plain_a[i] << " ";
  //   }
  // }
  // cout << endl;
  for (int i = 0; i < size; i++)
  {
    twoA[i] = RSSMulConst(a[i], 2L);
  }
  // uint64_t *plain_twoA = RSSRect(twoA, size, th);
  // cout << "plain_twoA: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   if (plain_twoA[i] > primeT)
  //   {
  //     cout << "-" << (prime - plain_twoA[i]) << " ";
  //   }
  //   else
  //   {
  //     cout << plain_twoA[i] << " ";
  //   }
  // }
  // cout << endl;
  uint64_t **tmpMSB = new uint64_t *[size];
  for (int i = 0; i < size; i++)
  {
    tmpMSB[i] = new uint64_t[2];
    for (int j = 0; j < 2; j++)
    {
      tmpMSB[i][j] = getMSB(a[i][j]);
    }
  }
  cmp = funcWrap(twoA, beta, r, shares_r, alpha, tmpMSB, size, th);
  // uint64_t *plain_cmp = RSSRect(cmp, size, th);
  // cout << "plain_cmp: \t\n ";
  // for (int i = 0; i < size; ++i)
  // {
  //   cout << plain_cmp[i] << " ";
  // }
  // cout << endl;

  // uint64_t **msbXOR = funcCrunchXOR(tmp, size, th);
  // for (int i = 0; i < size; i++)
  // {
  //   cmp[i] = RSSXOR(msbXOR[i], cmp[i], th);
  // }
  for (int i = 0; i < size; i++)
  {
    delete[] twoA[i];
    delete[] tmpMSB[i];
    // delete[] msbXOR[i];
  }
  delete[] twoA;
  delete[] tmpMSB;
  // delete[] msbXOR;
  return cmp;
}

int GetSum(uint64_t **Ind, int size, int th)
{
  uint64_t **Indt = new uint64_t *[1];
  Indt[0] = RSSSum(Ind, size);
  uint64_t *plain_Sum = RSSRect(Indt, 1, th);
  delete[] Indt;
  return (int)plain_Sum[0];
}

uint64_t **funcprefixOr(uint64_t **cmp, int size, int th)
{
  uint64_t **prefixOr = new uint64_t *[size];
  prefixOr[0] = new uint64_t[2];
  prefixOr[0][0] = cmp[0][0];
  prefixOr[0][1] = cmp[0][1];
  for (int i = 1; i < size; i++)
  {
    // (a+b)-a*b = a U b
    prefixOr[i] = RSSSub((RSSAdd(prefixOr[i - 1], cmp[i])), RSSMul(prefixOr[i - 1], cmp[i], th));
  }
  return prefixOr;
}

void funcPrivateSelect(uint64_t **cmp, uint64_t ***&new_V, uint64_t ***V, int new_size, int size, int th)
{
  // uint64_t **cmpt = new uint64_t *[size];
  // for (int i = 0; i < size; i++)
  // {
  //   cmpt[i] = new uint64_t[2];
  //   cmpt[i][0] = cmp[i][0];
  //   cmpt[i][1] = cmp[i][1];
  // }
  for (int j = 0; j < new_size; j++)
  {
    uint64_t **ind = new uint64_t *[size];
    // uint64_t **prefixOr = funcprefixOr(cmpt, size, th);
    uint64_t **prefixOr = funcprefixOr(cmp, size, th);
    ind[0] = new uint64_t[2];
    ind[0][0] = prefixOr[0][0];
    ind[0][1] = prefixOr[0][1];
    for (int i = 1; i < size; i++)
    {
      ind[i] = RSSSub(prefixOr[i], prefixOr[i - 1]);
    }
    for (int i = 0; i < size; i++)
    {
      // cmpt[i] = RSSSub(cmpt[i], ind[i]);
      cmp[i] = RSSSub(cmp[i], ind[i]);
    }
    // uint64_t *Indt = RSSRect(ind, size, th);
    // for (int j = 0; j < size; ++j)
    // {
    //   cout << Indt[j] << " ";
    // }
    // cout << endl;
    for (int i = 0; i < m; i++)
    {
      uint64_t **tmp = RSSDotMul(ind, V[i], size, th);
      new_V[i][j] = RSSSum(tmp, size);
      delete[] tmp;
    }
    for (int i = 0; i < size; i++)
    {
      delete[] ind[i];
      delete[] prefixOr[i];
    }
    delete[] ind;
    delete[] prefixOr;
  }
  // delete[] cmpt;
}

// void funcPrivateSelect(uint64_t **cmp, int s, uint64_t ***&new_V, uint64_t ***V, int new_size, int size, int th)
// {
//   uint64_t **cmpt = new uint64_t *[size];
//   for (int i = 0; i < size; i++)
//   {
//     cmpt[i] = new uint64_t[2];
//     cmpt[i][0] = cmp[s + i][0];
//     cmpt[i][1] = cmp[s + i][1];
//   }
//   for (int j = 0; j < new_size; j++)
//   {
//     uint64_t **ind = new uint64_t *[size];
//     uint64_t **prefixOr = funcprefixOr(cmpt, size, th);
//     ind[0] = new uint64_t[2];
//     ind[0][0] = prefixOr[0][0];
//     ind[0][1] = prefixOr[0][1];
//     for (int i = 1; i < size; i++)
//     {
//       ind[i] = RSSSub(prefixOr[i], prefixOr[i - 1]);
//     }
//     for (int i = 0; i < size; i++)
//     {
//       cmpt[i] = RSSSub(cmpt[i], ind[i]);
//     }
//     // uint64_t *Indt = RSSRect(ind, size, th);
//     // for (int j = 0; j < size; ++j)
//     // {
//     //   cout << Indt[j] << " ";
//     // }
//     // cout << endl;
//     for (int i = 0; i < m; i++)
//     {
//       uint64_t **tmp = RSSDotMul(ind, V[i], size, th);
//       new_V[i][j] = RSSSum(tmp, size);
//       delete[] tmp;
//     }
//     for (int i = 0; i < size; i++)
//     {
//       delete[] ind[i];
//       delete[] prefixOr[i];
//     }
//     delete[] ind;
//     delete[] prefixOr;
//   }
//   delete[] cmpt;
// }

uint64_t ***funcQueryLoc(uint64_t **SS_Q, int &len)
{
  mal_time = 0;
  double s0 = omp_get_wtime();
  // uint64_t q[] = {6 * 2, 7 * 2};
  string filepath1 = file_prevM + "model" + to_string(branch) + "_" + to_string(partyNum) + ".txt";
  string filepath2 = file_prevM + "model" + to_string(branch) + "_" + to_string(next_party[partyNum]) + ".txt";
  ifstream inf;
  inf.open(filepath1);
  string line;
  getline(inf, line);
  istringstream sin0(line);
  string field0;
  getline(sin0, field0, ';');
  // m = (uint32_t)stoi(field0);
  getline(sin0, field0, ';');
  depth = (uint32_t)stoi(field0) + 1;
  // getline(sin0, field0, ';');
  // branch = (uint32_t)stoi(field0);
  inf.close();
  cout << m << "," << depth << "," << branch << endl;
  tree1 = new RT(branch, 2);
  tree2 = new RT(branch, 2);
  // cout << "tree input" << endl;
  try
  {
#pragma omp parallel num_threads(2)
    {
#pragma omp single
      {
#pragma omp task firstprivate(tree1, filepath1)
        {
          read_model(tree1, filepath1);
        }
#pragma omp task firstprivate(tree2, filepath2)
        {
          read_model(tree2, filepath2);
        }
#pragma omp taskwait
      }
    }
  }
  catch (exception &e)
  {
    throw runtime_error(e.what());
  }
  // cout << "tree finish" << endl;
  // int m = tree1->dimension;
  // int depth = tree1->root->level + 1;
  Cmp_r = new uint64_t[2];
  Cmp_shares_r = new uint64_t *[BIT_SIZE];
  Cmp_alpha = new uint64_t[2];
  Cmp_beta = new uint64_t[2];
  Verif_x = new uint64_t[2];
  Verif_y = new uint64_t[2];
  Verif_z = new uint64_t[2];
  read_Random({file_prevR + "random_" + to_string(partyNum) + ".txt", file_prevR + "random_" + to_string(next_party[partyNum]) + ".txt"}, Cmp_r, Cmp_shares_r, Cmp_alpha, Cmp_beta, Verif_x, Verif_y, Verif_z);
  cout << "Finish_pre" << endl;
  int curSpace = 1;
  int newSize = tree1->root->usedSpace;
  uint64_t ***SSV = new uint64_t **[newSize];
  RTNode **node1 = new RTNode *[1];
  RTNode **node2 = new RTNode *[1];
  double s1 = omp_get_wtime();
  node1[0] = (RTDirNode *)tree1->root;
  node2[0] = (RTDirNode *)tree2->root;
  int th = 0;
  // int dimension = 2;
  // omp_set_nested(4);
  for (int itr = 0; itr < depth; itr++)
  {
    int index = 0;
    // cout << "curSpace:" << curSpace << endl;
    // cout << "newSize:" << newSize << endl;
    // select threshold from rtree
    for (int i = 0; i < curSpace; i++)
    {
      for (int j = 0; j < node1[i]->usedSpace; j++)
      {
        SSV[index] = new uint64_t *[4];
        for (int t = 0; t < 4; t++)
        {
          SSV[index][t] = new uint64_t[2];
        }
        for (int t = 0; t < 2; t++)
        {
          SSV[index][t][0] = node1[i]->getdatas(j)->getLow()->get(t);
          SSV[index][t][1] = node2[i]->getdatas(j)->getLow()->get(t);
          // cout << node1[i]->getdatas(j)->getLow()->get(t) << "," << node2[i]->getdatas(j)->getLow()->get(t) << endl;
        }
        for (int t = 0; t < 2; t++)
        {
          SSV[index][t + 2][0] = node1[i]->getdatas(j)->getHigh()->get(t);
          SSV[index][t + 2][1] = node2[i]->getdatas(j)->getHigh()->get(t);
          // cout << index << "," << SSV[index][t + m][0] << "," << SSV[index][t + m][1] << endl;
        }
        index++;
      }
    }
    double s21 = omp_get_wtime();
    int size = newSize * 2;
    uint64_t **tmpVt = new uint64_t *[size];
    // uint64_t **tmpV1 = new uint64_t *[newSize];
    // uint64_t **tmpV2 = new uint64_t *[newSize];
    for (int i = 0; i < newSize; i++)
    {
      for (int k = 0; k < 2; k++)
      {
        // considering the case that (Q-A1)*(Q-A2)=0, sub the extra 1L.
        tmpVt[i * 2 + k] = RSSSubConst(RSSMul(RSSSub(SS_Q[k], SSV[i][k]), RSSSub(SS_Q[k], RSSSubConst(SSV[i][2 + k], 1L)), th), 1L);
      }
      // tmpV1[i] = RSSSubConst(RSSMul(RSSSub(SS_Q[0], SSV[i][0]), RSSSub(SS_Q[0], RSSSubConst(SSV[i][2], 1L)), th), 1L);
      // tmpV2[i] = RSSSubConst(RSSMul(RSSSub(SS_Q[1], SSV[i][1]), RSSSub(SS_Q[1], RSSSubConst(SSV[i][3], 1L)), th), 1L);
    }
    // double s01 = omp_get_wtime();
    uint64_t **tmpInd = funcMsb(tmpVt, Cmp_r, Cmp_shares_r, Cmp_alpha, Cmp_beta, size, th);
    // uint64_t **tmpInd1 = funcMsb(tmpV1, Cmp_r, Cmp_shares_r, Cmp_alpha, Cmp_beta, newSize, th);
    // uint64_t **tmpInd2 = funcMsb(tmpV2, Cmp_r, Cmp_shares_r, Cmp_alpha, Cmp_beta, newSize, th);
    uint64_t **Indt = funcLoopMultiply(tmpInd, size, 2, th);
    // uint64_t **Indt = RSSDotMul(tmpInd1, tmpInd2, newSize, th);
    // pruning
    // double s32 = omp_get_wtime();
    if (!node1[0]->isLeaf())
    {
      uint64_t *Ind = RSSRect(Indt, newSize, th);
      // for (int j = 0; j < newSize; ++j)
      // {
      //   cout << Ind[j] << " ";
      // }
      // cout << endl;
      int old_curSpace = curSpace;
      curSpace = 0;
      for (int i = 0; i < newSize; i++)
      {
        curSpace += Ind[i];
      }
      cout << "level:" << node1[0]->level << " ";
      newSize = 0;
      index = 0;
      int k = 0;
      RTNode **node1t = new RTNode *[curSpace];
      RTNode **node2t = new RTNode *[curSpace];
      for (int i = 0; i < old_curSpace; i++)
      {
        for (int j = 0; j < node1[i]->usedSpace; j++)
        {
          if (Ind[index] == 1)
          {
            node1t[k] = ((RTDirNode *)node1[i])->getChild(j);
            node2t[k] = ((RTDirNode *)node2[i])->getChild(j);
            newSize += node1t[k]->usedSpace;
            k++;
          }
          // else
          // {
          //   skyR1.push_back(((RTDirNode *)node1[i])->getChild(j));
          //   skyR2.push_back(((RTDirNode *)node2[i])->getChild(j));
          // }
          index++;
        }
      }
      delete[] SSV;
      SSV = new uint64_t **[newSize];
      delete[] node1;
      delete[] node2;
      node1 = node1t;
      node2 = node2t;
      delete[] Ind;
    }
    else
    {
      // uint64_t *Ind = RSSRect(Indt, newSize, th);
      // for (int j = 0; j < newSize; ++j)
      // {
      //   cout << Ind[j] << " ";
      // }
      // cout << endl;
      cout << "leaf: ";
      // // Plain
      // index = 0;
      // newSize = 0;
      // for (int i = 0; i < old_curSpace; i++)
      // {
      //   for (int j = 0; j < node1[i]->usedSpace; j++)
      //   {
      //     if (Ind[index] == 1)
      //     {
      //       SSV[newSize] = new uint64_t *[m];
      //       for (int t = 0; t < m; t++)
      //       {
      //         SSV[newSize][t] = new uint64_t[2];
      //         SSV[newSize][t][0] = ((RTDataNode *)node1[i])->getdata(j)->get(t);
      //         SSV[newSize][t][1] = ((RTDataNode *)node2[i])->getdata(j)->get(t);
      //       }
      //       newSize++;
      //     }
      //     index++;
      //   }
      // }
      // Select
      int old_Size = newSize;
      newSize = GetSum(Indt, newSize, th);
      // cout << old_Size << "," << newSize << endl;
      delete[] SSV;
      SSV = new uint64_t **[newSize];
      uint64_t ***Prev_SSV = new uint64_t **[m];
      uint64_t ***SSV_sp = new uint64_t **[m];
      for (int i = 0; i < newSize; i++)
      {
        SSV[i] = new uint64_t *[m];
        for (int k = 0; k < m; k++)
        {
          SSV[i][k] = new uint64_t[2];
        }
      }
      int index = 0;
      int sp = 0;
      for (int i = 0; i < curSpace; i++)
      {
        int size_sp = node1[i]->usedSpace;
        uint64_t **Indt_sp = new uint64_t *[size_sp];
        for (int j = 0; j < size_sp; j++)
        {
          Indt_sp[j] = new uint64_t[2];
          for (int k = 0; k < 2; k++)
          {
            Indt_sp[j][k] = Indt[j + index][k];
          }
        }
        index += size_sp;
        int newSize_sp = GetSum(Indt_sp, size_sp, th);
        for (int t = 0; t < m; t++)
        {
          SSV_sp[t] = new uint64_t *[size_sp];
          Prev_SSV[t] = new uint64_t *[size_sp];
          for (int j = 0; j < size_sp; j++)
          {
            Prev_SSV[t][j] = new uint64_t[2];
            Prev_SSV[t][j][0] = ((RTDataNode *)node1[i])->getdata(j)->get(t);
            Prev_SSV[t][j][1] = ((RTDataNode *)node2[i])->getdata(j)->get(t);
          }
        }
        funcPrivateSelect(Indt_sp, SSV_sp, Prev_SSV, newSize_sp, size_sp, th);
        for (int j = 0; j < newSize_sp; j++)
        {
          for (int t = 0; t < m; t++)
          {
            for (int k = 0; k < 2; k++)
            {
              SSV[sp][t][k] = SSV_sp[t][j][k];
            }
          }
          sp++;
        }
        delete[] Indt_sp;
      }
      /*
      SSV = new uint64_t **[m];
      uint64_t ***Prev_SSV = new uint64_t **[m];
      for (int t = 0; t < m; t++)
      {
        Prev_SSV[t] = new uint64_t *[old_Size];
        SSV[t] = new uint64_t *[newSize];
      }
      int index = 0;
      for (int i = 0; i < curSpace; i++)
      {
        for (int j = 0; j < node1[i]->usedSpace; j++)
        {
          for (int t = 0; t < m; t++)
          {
            Prev_SSV[t][index] = new uint64_t[2];
            Prev_SSV[t][index][0] = ((RTDataNode *)node1[i])->getdata(j)->get(t);
            Prev_SSV[t][index][1] = ((RTDataNode *)node2[i])->getdata(j)->get(t);
          }
          index++;
        }
      }
      funcPrivateSelect(Indt, SSV, Prev_SSV, newSize, old_Size, th);
      */
      delete[] Prev_SSV;
    }
    // double s33 = omp_get_wtime();
    // cout << "funcQuery-select-" << itr << ":" << (s33 - s32) << "s" << endl;
    // cout << "===========================" << endl;
    double s22 = omp_get_wtime();
    cout << "funcQuery-" << itr << ":" << (s22 - s21) << "s" << endl;
    // for (int i = 0; i < size; i++)
    // {
    //   delete[] tmpVt[i];
    //   delete[] tmpInd[i];
    // }
    // // for (int i = 0; i < size/2; i++)
    // // {
    // //   delete[] tmpInd1[i];
    // //   delete[] tmpInd2[i];
    // // }
    // for (int i = 0; i < size / 2; i++)
    // {
    //   delete[] Indt[i];
    // }
    delete[] tmpVt;
    // delete[] tmpInd1;
    // delete[] tmpInd2;
    delete[] tmpInd;
    delete[] Indt;
  }
  double s2 = omp_get_wtime();
  len = newSize;
  cout << "len:" << newSize << endl;
  // for (int i = 0; i < newSize; i++)
  // {
  //   uint64_t *plain_V = RSSRect(SSV[i], m, th);
  //   for (int j = 0; j < m - 1; ++j)
  //   {
  //     cout << (plain_V[j] / 2) << "\t";
  //   }
  //   cout << (plain_V[m - 1] / 2) << endl;
  // }
  cout << "PreQuery Time\t" << RED << (s1 - s0) << " s" << RESET << endl;
  cout << "funcQuery Time\t" << RED << (s2 - s1) << " s" << RESET << endl;
  pre_time = s1 - s0;
  que_time = s2 - s1;
  delete[] Cmp_shares_r;
  delete[] Cmp_alpha;
  delete[] Cmp_beta;
  delete[] Verif_x;
  delete[] Verif_y;
  delete[] Verif_z;
  delete tree1;
  delete tree2;
  delete[] node1;
  delete[] node2;
  // delete[] SSV;
  return SSV;
}

void shar()
{
  int size = 10;
  uint64_t *Si = new uint64_t[size];
  uint64_t *Ci = new uint64_t[size];
  cout << prime << endl;
  prg.random_data(Si, size * sizeof(uint64_t));
  for (int i = 0; i < size; i++)
  {
    cout << Si[i] << ",";
  }
  cout << endl;
#pragma omp parallel num_threads(2)
  {
#pragma omp single
    {
#pragma omp task firstprivate(size)
      {
        Iot[0]->recv_data(Ci, size * sizeof(uint64_t));
      }
#pragma omp task firstprivate(size)
      {
        Iot[1]->send_data(Si, size * sizeof(uint64_t));
      }
#pragma omp taskwait
    }
  }
  // Iot[0]->send_data(Si, size * sizeof(uint64_t));
  // Iot[1]->recv_data(Ci, size * sizeof(uint64_t));
  cout << " recv" << endl;
  for (int i = 0; i < size; i++)
  {
    cout << Ci[i] << ",";
  }
  cout << endl;

  uint64_t **Ti = new uint64_t *[size];

  for (int i = 0; i < size; i++)
  {
    Ti[i] = new uint64_t[2];
    Ti[i][0] = Si[i] % 100;
    Ti[i][1] = Ci[i] % 100;
  }
  uint64_t *Ki = RSSRect(Ti, size, 0);
  for (int i = 0; i < size; i++)
  {
    cout << Ki[i] << ",";
  }
  cout << endl;
}

int mainO(int argc, char **argv)
{
  ArgMapping amap;
  amap.arg("r", partyNum, "Role of party: ALICE = 1; BOB = 2; CHARLIE = 3");
  amap.arg("pS", portS, "Port Number");
  amap.arg("pC", portC, "Port Number");
  amap.arg("ip", address, "IP Address of server");
  amap.parse(argc, argv);
  for (int i = 0; i < THs; i = i + 2)
  {
#pragma omp parallel num_threads(2)
    {
#pragma omp single
      {
#pragma omp task firstprivate(portS, portC, partyNum, i)
        {
          Iot[i] = new NetIO(address.c_str(), portS + i * 3);
        }
#pragma omp task firstprivate(portS, portC, partyNum, i)
        {
          Iot[i + 1] = new NetIO(nullptr, portC + i * 3);
        }
#pragma omp taskwait
      }
    }
  }
  srand(time(0) + partyNum);
  // shar();
  cout << "Party:" << partyNum << endl;

  uint64_t ***SS_Q = new uint64_t **[10];
  for (int q_Num = 0; q_Num < 10; q_Num++)
  {
    SS_Q[q_Num] = new uint64_t *[2];
    for (int i = 0; i < 2; i++)
    {
      SS_Q[q_Num][i] = new uint64_t[2];
    }
  }
  string path[3] = {"/small-correlate.txt", "/small-anti-corr.txt", "/small-uniformly.txt"};
  string pathF[3] = {"/small-correlate/", "/small-anti-corr/", "/small-uniformly/"};
  int N[6] = {1000, 3000, 5000, 7000, 9000, 11000};
  int dim[5] = {3, 4, 5, 6, 7};
  // SECURITY_TYPE = "Semi-honest";
  SECURITY_TYPE = "Malicious";
  string typeM[2] = {"Semi-honest", "Malicious"};
  for (int k = 1; k < 2; k++)
  {
    for (int i = 0; i < 1; i++)
    {
      for (int j = 0; j < 3; j++)
      {
        for (int bran = 3; bran <= 7; bran++)
        {
          m = dim[k];
          branch = bran;
          file_prevM = "./params/data" + to_string(dim[k]) + "/input=" + to_string(domain) + "/size=" + to_string(N[j]) + "/model" + pathF[i];
          file_prevQ = "./params/data" + to_string(dim[k]) + "/input=" + to_string(domain) + "/size=" + to_string(N[j]) + "/query" + pathF[i];
          file_prevR = "./params/data" + to_string(dim[k]) + "/input=" + to_string(domain) + "/size=" + to_string(N[j]) + "/random" + pathF[i];
          read_Query({file_prevQ + "query_" + to_string(partyNum) + ".txt", file_prevQ + "query_" + to_string(next_party[partyNum]) + ".txt"}, SS_Q, 10);
          double Qtime = 0, QCom = 0, Qpre = 0, Qque = 0, Qmal = 0, Qlen = 0;
          int itrs = 10;
          for (int itr = 0; itr < itrs; itr++)
          {
            int len = 0;
            uint64_t *plain_q = RSSRect(SS_Q[itr], 2, 0);
            for (int k = 0; k < 2; k++)
            {
              cout << plain_q[k] / 2 << ",";
            }
            cout << endl;
            delete[] plain_q;
            uint64_t comm_start = 0;
            for (int j = 0; j < THs; j++)
            {
              comm_start += Iot[j]->counter;
            }
            double start = omp_get_wtime();
            funcQueryLoc(SS_Q[itr], len);
            double end = omp_get_wtime();
            Qtime += end - start;
            uint64_t comm_end = 0;
            for (int j = 0; j < THs; j++)
            {
              comm_end += Iot[j]->counter;
            }
            QCom += comm_end - comm_start;
            Qpre += pre_time;
            Qque += que_time;
            Qmal += mal_time;
            Qlen += len;
          }
          Qtime = Qtime / itrs;
          QCom = QCom / itrs / 1024;
          Qpre = Qpre / itrs;
          Qque = Qque / itrs;
          Qmal = Qmal / itrs;
          Qlen = Qlen / itrs;
          if (SECURITY_TYPE.compare("Malicious") == 0)
          {
            cout << "n = " + to_string(N[j]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Mal" << endl;
          }
          else
          {
            cout << "n = " + to_string(N[j]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Semi" << endl;
          }
          cout << "CS_" + to_string(partyNum) + " Skyline Number\t" << RED << Qlen << RESET << endl;
          cout << "CS_" + to_string(partyNum) + " Total Time\t" << RED << Qtime << " s" << RESET << endl;
          cout << "CS_" + to_string(partyNum) + " Read Time\t" << RED << Qpre << " s" << RESET << endl;
          cout << "CS_" + to_string(partyNum) + " Query Time\t" << RED << Qque << " s" << RESET << endl;
          cout << "CS_" + to_string(partyNum) + " Verify Time\t" << RED << Qmal << " s" << RESET << endl;
          cout << "CS_" + to_string(partyNum) + " Communication\t" << BLUE << QCom << " KB" << RESET << endl;
          ofstream outfile;
          if (SECURITY_TYPE.compare("Malicious") == 0)
          {
            outfile.open("../../tests/out_" + to_string(partyNum) + "_M.txt", ios::app | ios::in);
          }
          else
          {
            outfile.open("../../tests/out_" + to_string(partyNum) + ".txt", ios::app | ios::in);
          }
          outfile << " -------------------------------------" << endl;
          if (SECURITY_TYPE.compare("Malicious") == 0)
          {
            outfile << "n = " + to_string(N[j]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Mal" << endl;
          }
          else
          {
            outfile << "n = " + to_string(N[j]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Semi" << endl;
          }
          // outfile << "n = " + to_string(N[j]) + " " + file_prevM + " with Mal" << endl;
          outfile << "CS_" + to_string(partyNum) + " Skyline Number:" << Qlen << endl;
          outfile << "CS_" + to_string(partyNum) + " Total Time:" << Qtime << " s" << endl;
          outfile << "CS_" + to_string(partyNum) + " Read Time:" << Qpre << " s" << endl;
          outfile << "CS_" + to_string(partyNum) + " Query Time:" << Qque << " s" << endl;
          outfile << "CS_" + to_string(partyNum) + " Verify Time:" << Qmal << " s" << endl;
          outfile << "CS_" + to_string(partyNum) + " Communication:" << QCom << " KB" << endl;
          outfile << " -------------------------------------" << endl;
          outfile.close();
        }
      }
    }
  }
  /*
  // hotel data
  for (int k = 0; k < 5; k++)
  {
    for (int j = 0; j < 1; j++)
    {
      for (int bran = 3; bran <= 7; bran++)
      {
        m = dim[k];
        branch = bran;
        file_prevM = "./params/data" + to_string(dim[k]) + "/hotel" + "/size=" + to_string(N[j]) + "/model/";
        file_prevQ = "./params/data" + to_string(dim[k]) + "/hotel" + "/size=" + to_string(N[j]) + "/query/";
        file_prevR = "./params/data" + to_string(dim[k]) + "/hotel" + "/size=" + to_string(N[j]) + "/random/";
        read_Query({file_prevQ + "query_" + to_string(partyNum) + ".txt", file_prevQ + "query_" + to_string(next_party[partyNum]) + ".txt"}, SS_Q, 10);
        double Qtime = 0, QCom = 0, Qpre = 0, Qque = 0, Qmal = 0, Qlen = 0;
        int itrs = 10;
        for (int itr = 0; itr < itrs; itr++)
        {
          int len = 0;
          uint64_t *plain_q = RSSRect(SS_Q[itr], 2, 0);
          for (int k = 0; k < 2; k++)
          {
            cout << plain_q[k] / 2 << ",";
          }
          cout << endl;
          delete[] plain_q;
          uint64_t comm_start = 0;
          for (int j = 0; j < THs; j++)
          {
            comm_start += Iot[j]->counter;
          }
          double start = omp_get_wtime();
          funcQueryLoc(SS_Q[itr], len);
          double end = omp_get_wtime();
          Qtime += end - start;
          uint64_t comm_end = 0;
          for (int j = 0; j < THs; j++)
          {
            comm_end += Iot[j]->counter;
          }
          QCom += comm_end - comm_start;
          Qpre += pre_time;
          Qque += que_time;
          Qmal += mal_time;
          Qlen += len;
        }
        Qtime = Qtime / itrs;
        QCom = QCom / itrs / 1024;
        Qpre = Qpre / itrs;
        Qque = Qque / itrs;
        Qmal = Qmal / itrs;
        Qlen = Qlen / itrs;
        if (SECURITY_TYPE.compare("Malicious") == 0)
        {
          cout << "n = " + to_string(N[j]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Mal" << endl;
        }
        else
        {
          cout << "n = " + to_string(N[j]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Semi" << endl;
        }
        cout << "CS_" + to_string(partyNum) + " Skyline Number\t" << RED << Qlen << RESET << endl;
        cout << "CS_" + to_string(partyNum) + " Total Time\t" << RED << Qtime << " s" << RESET << endl;
        cout << "CS_" + to_string(partyNum) + " Read Time\t" << RED << Qpre << " s" << RESET << endl;
        cout << "CS_" + to_string(partyNum) + " Query Time\t" << RED << Qque << " s" << RESET << endl;
        cout << "CS_" + to_string(partyNum) + " Verify Time\t" << RED << Qmal << " s" << RESET << endl;
        cout << "CS_" + to_string(partyNum) + " Communication\t" << BLUE << QCom << " KB" << RESET << endl;
        ofstream outfile;
        outfile.open("../../tests/out_" + to_string(partyNum) + ".txt", ios::app | ios::in);
        outfile << " -------------------------------------" << endl;
        if (SECURITY_TYPE.compare("Malicious") == 0)
        {
          outfile << "n = " + to_string(N[j]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Mal" << endl;
        }
        else
        {
          outfile << "n = " + to_string(N[j]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Semi" << endl;
        }
        // outfile << "n = " + to_string(N[j]) + " " + file_prevM + " with Mal" << endl;
        outfile << "CS_" + to_string(partyNum) + " Skyline Number:" << Qlen << endl;
        outfile << "CS_" + to_string(partyNum) + " Total Time:" << Qtime << " s" << endl;
        outfile << "CS_" + to_string(partyNum) + " Read Time:" << Qpre << " s" << endl;
        outfile << "CS_" + to_string(partyNum) + " Query Time:" << Qque << " s" << endl;
        outfile << "CS_" + to_string(partyNum) + " Verify Time:" << Qmal << " s" << endl;
        outfile << "CS_" + to_string(partyNum) + " Communication:" << QCom << " KB" << endl;
        outfile << " -------------------------------------" << endl;
        outfile.close();
      }
    }
  }
  */
  for (int i = 0; i < THs; i++)
  {
    delete Iot[i];
  }
  return 0;
}

int main(int argc, char **argv)
{
  ArgMapping amap;
  amap.arg("r", partyNum, "Role of party: ALICE = 1; BOB = 2; CHARLIE = 3");
  amap.arg("pS", portS, "Port Number");
  amap.arg("pC", portC, "Port Number");
  amap.arg("ip", address, "IP Address of server");
  amap.arg("Pdim", Pd, "data dim");
  amap.arg("Pname", Pn, "data name");
  amap.arg("Psize", Pst, "data size");
  amap.arg("Pbran", Pb, "branch");
  // amap.arg("Pitr", Pit, "itr");
  amap.parse(argc, argv);
  for (int i = 0; i < THs; i = i + 2)
  {
#pragma omp parallel num_threads(2)
    {
#pragma omp single
      {
#pragma omp task firstprivate(portS, portC, partyNum, i)
        {
          Iot[i] = new NetIO(address.c_str(), portS + i * 3);
        }
#pragma omp task firstprivate(portS, portC, partyNum, i)
        {
          Iot[i + 1] = new NetIO(nullptr, portC + i * 3);
        }
#pragma omp taskwait
      }
    }
  }
  srand(time(0) + partyNum);
  // shar();
  cout << "Party:" << partyNum << endl;

  uint64_t ***SS_Q = new uint64_t **[10];
  for (int q_Num = 0; q_Num < 10; q_Num++)
  {
    SS_Q[q_Num] = new uint64_t *[2];
    for (int i = 0; i < 2; i++)
    {
      SS_Q[q_Num][i] = new uint64_t[2];
    }
  }
  string path[3] = {"/small-correlate.txt", "/small-anti-corr.txt", "/small-uniformly.txt"};
  string pathF[3] = {"/small-correlate/", "/small-anti-corr/", "/small-uniformly/"};
  // int N[6] = {1000, 3000, 5000, 7000, 9000, 11000};
  int N[1] = {100000};
  int dim[5] = {3, 4, 5, 6, 7};
  // SECURITY_TYPE = "Semi-honest";
  SECURITY_TYPE = "Malicious";
  string typeM[2] = {"Semi-honest", "Malicious"};

  // Pd = 1, Pn = 0, Pst = 0, Pb = 3;

  m = dim[Pd];
  branch = Pb;
  file_prevM = "./params/data" + to_string(m) + "/input=" + to_string(domain) + "/size=" + to_string(N[Pst]) + "/model" + pathF[Pn];
  file_prevQ = "./params/data" + to_string(m) + "/input=" + to_string(domain) + "/size=" + to_string(N[Pst]) + "/query" + pathF[Pn];
  file_prevR = "./params/data" + to_string(m) + "/input=" + to_string(domain) + "/size=" + to_string(N[Pst]) + "/random" + pathF[Pn];
  read_Query({file_prevQ + "query_" + to_string(partyNum) + ".txt", file_prevQ + "query_" + to_string(next_party[partyNum]) + ".txt"}, SS_Q, 10);
  double Qtime = 0, QCom = 0, Qpre = 0, Qque = 0, Qmal = 0, Qlen = 0;
  int itrs = 10;
  // int itri[6] = {0,2,4,6,8,10};
  // int indexi =Pit;
  // for (int itr = itri[indexi]; itr < itri[indexi+1]; itr++)
  for (int itr = 0; itr < itrs; itr++)
  {
    int len = 0;
    uint64_t *plain_q = RSSRect(SS_Q[itr], 2, 0);
    cout << itr << "-itr:\t";
    for (int k = 0; k < 2; k++)
    {
      cout << plain_q[k] / 2 << ",";
    }
    cout << endl;

    uint64_t comm_start = 0;
    for (int j = 0; j < THs; j++)
    {
      comm_start += Iot[j]->counter;
    }
    double start = omp_get_wtime();
    uint64_t ***SSV = funcQueryLoc(SS_Q[itr], len);
    double end = omp_get_wtime();
    Qtime += end - start;
    uint64_t comm_end = 0;
    for (int j = 0; j < THs; j++)
    {
      comm_end += Iot[j]->counter;
    }
    QCom += comm_end - comm_start;
    Qpre += pre_time;
    Qque += que_time;
    Qmal += mal_time;
    Qlen += len;
    //   string data_path = "./data/data" + to_string(m) + "/input=" + to_string(domain) + "/size=" + to_string(N[Pst]) + path[Pn];
    //   vector<vector<uint64_t>> p;
    //   loadP(p, data_path);
    //   uint64_t *plain_Sky = plainT(p, plain_q, N[Pst], dim[Pd]);
    //   delete[] plain_q;
    //   for (int i = 0; i < len; i++)
    // {
    //   for (int j = 0; j < m; j++)
    //   {
    //     cout << plain_Sky[i*m+j] << "\t";
    //   }
    //   cout << endl;
    // }
    // for (int i = 0; i < len; i++)
    //   {
    //     uint64_t *plain_V = RSSRect(SSV[i], m, 0);
    //     for (int j = 0; j < m; ++j)
    //     {
    //       cout << (plain_V[j] / 2) << "\t";
    //     }
    //     cout << endl;
    //   }
  }
  Qtime = Qtime / itrs;
  QCom = QCom / itrs / 1024 / 1024;
  Qpre = Qpre / itrs;
  Qque = Qque / itrs;
  Qmal = Qmal / itrs;
  Qlen = Qlen / itrs;
  if (SECURITY_TYPE.compare("Malicious") == 0)
  {
    cout << "n = " + to_string(N[Pst]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Mal" << endl;
  }
  else
  {
    cout << "n = " + to_string(N[Pst]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Semi" << endl;
  }
  cout << "CS_" + to_string(partyNum) + " Skyline Number\t" << RED << Qlen << RESET << endl;
  cout << "CS_" + to_string(partyNum) + " Total Time\t" << RED << Qtime << " s" << RESET << endl;
  cout << "CS_" + to_string(partyNum) + " Read Time\t" << RED << Qpre << " s" << RESET << endl;
  cout << "CS_" + to_string(partyNum) + " Query Time\t" << RED << Qque << " s" << RESET << endl;
  cout << "CS_" + to_string(partyNum) + " Verify Time\t" << RED << Qmal << " s" << RESET << endl;
  cout << "CS_" + to_string(partyNum) + " Communication\t" << BLUE << QCom << " MB" << RESET << endl;
  ofstream outfile;
  if (SECURITY_TYPE.compare("Malicious") == 0)
  {
    outfile.open("../../tests/out_" + to_string(partyNum) + "_M.txt", ios::app | ios::in);
  }
  else
  {
    outfile.open("../../tests/out_" + to_string(partyNum) + ".txt", ios::app | ios::in);
  }
  outfile << " -------------------------------------" << endl;
  if (SECURITY_TYPE.compare("Malicious") == 0)
  {
    outfile << "n = " + to_string(N[Pst]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Mal" << endl;
  }
  else
  {
    outfile << "n = " + to_string(N[Pst]) + ", branch = " + to_string(branch) + " " + file_prevM + " with Semi" << endl;
  }
  // outfile << "n = " + to_string(N[Pst]) + " " + file_prevM + " with Mal" << endl;
  outfile << "CS_" + to_string(partyNum) + " Skyline Number:" << Qlen << endl;
  outfile << "CS_" + to_string(partyNum) + " Total Time:" << Qtime << " s" << endl;
  outfile << "CS_" + to_string(partyNum) + " Read Time:" << Qpre << " s" << endl;
  outfile << "CS_" + to_string(partyNum) + " Query Time:" << Qque << " s" << endl;
  outfile << "CS_" + to_string(partyNum) + " Verify Time:" << Qmal << " s" << endl;
  outfile << "CS_" + to_string(partyNum) + " Communication:" << QCom << " MB" << endl;
  outfile << " -------------------------------------" << endl;
  outfile.close();

  for (int i = 0; i < THs; i++)
  {
    delete Iot[i];
  }
  return 0;
}
